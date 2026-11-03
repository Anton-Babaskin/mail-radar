"""Production-shaped MIAB contracts absent from the original 119-case suite."""
import contextlib
from datetime import datetime, timezone
import io
import json
import lzma
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from mailradar import checks, cli
from mailradar.logs import analyze_logs
from mailradar.mailstore import collect_mailstore, header_delays
from mailradar.model import clean, finish_report, finding
from mailradar.runner import Result, permitted

ROOT=Path(__file__).resolve().parents[1]
FIXTURE=ROOT/'tests/fixtures/logs/miab-production-shapes.log'
SINCE=datetime(2026,11,3,10,tzinfo=timezone.utc)
UNTIL=datetime(2026,11,3,11,tzinfo=timezone.utc)


class Fake:
    def __init__(self,responses=None):
        self.responses=responses or {}
        self.history=[]
    def run(self,argv,timeout=8):
        if not permitted(argv):
            raise AssertionError(argv)
        self.history.append(argv)
        return self.responses.get(tuple(argv),Result(127,stderr='fixture unavailable',missing=True))


class MiabAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
    def write(self,path,text):
        target=self.root/path.lstrip('/')
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(text,encoding='utf-8')
        return str(target)
    def context(self,responses=None):
        args=cli.parser().parse_args([])
        args.root=str(self.root)
        return checks.Context(Fake(responses),args)
    def test_miab_submission_and_actual_lmtp_saved_form_are_recognized(self):
        result=analyze_logs([str(FIXTURE)],SINCE,UNTIL,timezone='Asia/Dubai',year=2026)
        stats=result['statistics']
        self.assertEqual(stats['top_authenticated_senders'],{'office@local.example':1})
        self.assertEqual(stats['outcomes'],{'next_smtp_accepted':1,'saved':1})
        self.assertEqual(stats['saved_log_events'],1)
        self.assertEqual(result['completeness']['unparsed_lines'],0)
        self.assertEqual(next(t for t in result['traces'] if t['queue_id']=='BCDEF01234')['outcome'],'saved')
    def test_background_relay_rejection_is_not_a_server_failure(self):
        result=analyze_logs([str(FIXTURE)],SINCE,UNTIL,timezone='Asia/Dubai')
        self.assertEqual(next(f for f in result['findings'] if f['id']=='MAIL-PREQUEUE-REJECT')['status'],'OK')
        targeted=analyze_logs([str(FIXTURE)],SINCE,UNTIL,timezone='Asia/Dubai',filters={'from':'spoofed@local.example'})
        self.assertEqual(next(f for f in targeted['findings'] if f['id']=='MAIL-PREQUEUE-REJECT')['status'],'WARN')
    def test_bounded_automatic_scan_keeps_recent_suffix_and_reports_missing_context(self):
        old='Nov  1 10:00:00 box postfix/qmgr[1]: ABCDE: removed\n'
        recent='Nov  3 14:25:00 box postfix/qmgr[1]: BCDEF: from=<s@sender.example>, size=1, nrcpt=1 (queue active)\n'
        path=self.write('/mail.log',old*100+recent)
        result=analyze_logs([path],SINCE,UNTIL,timezone='Asia/Dubai',recent=True,max_lines=2)
        self.assertEqual(result['statistics']['accepted_queue_events'],1)
        self.assertTrue(result['sources'][0]['prefix_omitted'])
        self.assertFalse(result['completeness']['complete'])
        self.assertLess(result['traces'][0]['events'][0]['line'],0)
        self.assertTrue(next(f for f in result['findings'] if f['id']=='LOG-SOURCE-INCOMPLETE')['evidence'])
    def test_rotation_priority_does_not_put_date_archives_before_current(self):
        with patch('mailradar.cli.glob.glob',return_value=['/var/log/mail.log.10.gz','/var/log/mail.log.2.gz','/var/log/mail.log.20261102.gz','/var/log/mail.log']):
            self.assertEqual(cli.default_logs(),['/var/log/mail.log','/var/log/mail.log.2.gz','/var/log/mail.log.10.gz','/var/log/mail.log.20261102.gz'])
    def test_cli_offset_and_display_zone_agree_on_python_39(self):
        stamp=cli.timestamp('2026-11-03T14:30:00.123456789+0400',timezone.utc)
        self.assertEqual(stamp.isoformat(),'2026-11-03T10:30:00.123456+00:00')
        from mailradar.display import _date
        self.assertEqual(_date(stamp.isoformat(),'Asia/Dubai'),'03.11 14:30 +0400')
    def test_duplicate_df_mount_is_reported_once(self):
        row='/dev/root 100 10 90 10% /\n'
        ctx=self.context({('df','-P','/'):Result(stdout='Filesystem 1024-blocks Used Available Capacity Mounted on\n'+row*3),('df','-Pi','/'):Result(stdout='Filesystem Inodes IUsed IFree IUse% Mounted on\n'+row*3)})
        checks.disk_checks(ctx)
        self.assertEqual(len([f for f in ctx.findings if f['id']=='DISK.SPACE']),1)
        self.assertEqual(len([f for f in ctx.findings if f['id']=='DISK.INODES']),1)
    def test_miab_spampd_does_not_require_spamassassin_daemon(self):
        responses={('systemctl','list-unit-files','--type=service','--no-legend','--no-pager'):Result(stdout='spampd.service enabled enabled\nspamassassin.service disabled enabled\n')}
        for name,state in [('spampd','active\nrunning\nloaded\n'),('spamassassin','inactive\ndead\nloaded\n')]:
            responses[('systemctl','show',name,'--property=LoadState,ActiveState,SubState','--value')]=Result(stdout=state)
        ctx=self.context(responses);ctx.miab=True
        checks.service_checks(ctx)
        self.assertEqual(next(f for f in ctx.findings if f['id']=='SERVICE.SPAMASSASSIN')['status'],'N/A')
        self.assertEqual(next(f for f in ctx.findings if f['id']=='SERVICE.SPAMPD')['status'],'OK')
    def test_failed_optional_service_is_not_hidden_as_disabled(self):
        ctx=self.context({('systemctl','list-unit-files','--type=service','--no-legend','--no-pager'):Result(stdout='spampd.service disabled enabled\n'),('systemctl','show','spampd','--property=LoadState,ActiveState,SubState','--value'):Result(stdout='loaded\nfailed\nfailed\n')})
        checks.service_checks(ctx)
        self.assertEqual(next(f for f in ctx.findings if f['id']=='SERVICE.SPAMPD')['status'],'WARN')
    def test_installed_postgrey_defaults_confirm_real_paths_without_execution(self):
        self.write('/usr/sbin/postgrey',"my $CONFIG_DIR = '/etc/postgrey';\nwhitelist_clients_files => $opt{'whitelist-clients'} || [\"$CONFIG_DIR/whitelist_clients\", \"$CONFIG_DIR/whitelist_clients.local\"],\n")
        self.write('/etc/postgrey/whitelist_clients','sender.example\n')
        self.write('/etc/postgrey/whitelist_clients.local','mx.partner.example\n')
        ctx=self.context({('systemctl','show','postgrey','--property=ExecStart','--value'):Result(stdout='{ path=/usr/sbin/postgrey ; argv[]=/usr/sbin/postgrey --inet=10023 ; }'),('systemctl','show','postgrey','--property=LoadState,ActiveState,SubState','--value'):Result(stdout='loaded\nactive\nrunning\n')})
        matches,unknown=checks.postgrey_whitelist_checks(ctx,'mx.partner.example',None)
        self.assertFalse(unknown)
        self.assertEqual(len(matches),1)
        self.assertTrue(all(f['status']=='OK' for f in ctx.findings if f['id']=='WHITELIST.POSTGREY_FILE'))
        self.assertFalse(any(argv[0]=='postgrey' for argv in ctx.runner.history))
    def test_runtime_postgrey_options_override_unit_placeholders(self):
        self.write('/proc/123/cmdline','/usr/sbin/postgrey\x00--whitelist-clients=/etc/postgrey/custom\x00')
        self.write('/etc/postgrey/custom','sender.example\n')
        ctx=self.context({('systemctl','show','postgrey','--property=ExecStart','--value'):Result(stdout='/usr/sbin/postgrey $POSTGREY_OPTS'),('systemctl','show','postgrey','--property=MainPID','--value'):Result(stdout='123\n'),('systemctl','show','postgrey','--property=LoadState,ActiveState,SubState','--value'):Result(stdout='loaded\nactive\nrunning\n')})
        matches,unknown=checks.postgrey_whitelist_checks(ctx,'mx.sender.example',None)
        self.assertFalse(unknown)
        self.assertEqual(matches[0]['file'],'/etc/postgrey/custom')
    def test_dovecot_null_headers_and_multiline_received_do_not_crash(self):
        self.assertIn('limitation',header_delays({'hdr.date':None,'hdr.received':None}))
        record={'hdr.date':'Mon, 2 Nov 2026 09:00:00 +0000','hdr.received':'from a.example\n by b.example; Mon, 2 Nov 2026 09:05:00 +0000\nfrom c.example; Mon, 2 Nov 2026 09:02:00 +0000'}
        self.assertEqual(header_delays(record)['date_to_earliest_received_seconds'],120)
    def test_dovecot_exact_message_id_time_scope_and_50_records_are_not_false_truncation(self):
        args=cli.parser().parse_args(['--headers','<one@example.org>','--user','office@local.example'])
        row={'mailbox':'Trash','hdr.message-id':'<one@example.org>','date.received.unixtime':SINCE.timestamp()+1,'hdr.date':None,'hdr.received':None}
        records=[row]*50+[dict(row,**{'hdr.message-id':'prefix<one@example.org>suffix'}),dict(row,**{'date.received.unixtime':UNTIL.timestamp()+1})]
        class StoreFake(Fake):
            def run(self,argv,timeout=8):
                self.history.append(argv)
                if 'fetch' in argv:
                    self.assertion=permitted(argv)
                    return Result(stdout=json.dumps(records))
                return Result(stdout='uid 1000\n')
        runner=StoreFake()
        with patch('mailradar.timeutil.local_zone',return_value=timezone.utc):
            result=collect_mailstore(runner,args,SINCE,UNTIL)
        metadata=next(f for f in result if f['id']=='mailstore.metadata')
        self.assertEqual(len(metadata['evidence']),50)
        self.assertFalse(metadata['details']['truncated'])
        self.assertEqual(metadata['status'],'OK')
        self.assertTrue(runner.assertion)
    def test_finite_json_and_dnsbl_secret_sanitization(self):
        result=finish_report({'findings':[finding('test','UNKNOWN','test',data=float('inf'))],'completeness':{'complete':False}})
        json.dumps(result,allow_nan=False)
        self.assertNotIn('secretkey',clean('blocked using secretkey.zen.dq.spamhaus.net'))
    def test_huge_numeric_log_fields_remain_unknown_instead_of_crashing(self):
        path=self.write('/numeric.log','2026-11-03T10:30:00Z box postfix/qmgr[1]: ABCDE: from=<x@example.org>, size='+'9'*5000+', nrcpt=1 (queue active)\n')
        result=analyze_logs([path],SINCE,UNTIL)
        self.assertEqual(result['statistics']['accepted_queue_events'],0)
        self.assertEqual(result['completeness']['unparsed_lines'],1)
    def test_lzma_dictionary_memory_is_bounded_and_concatenated_xz_works(self):
        line=b'2026-11-03T10:30:00Z box postfix/qmgr[1]: ABCDE: removed\n'
        valid=self.root/'valid.xz'
        valid.write_bytes(lzma.compress(line)+b'\0'*4+lzma.compress(line.replace(b'ABCDE',b'BCDEF')))
        result=analyze_logs([str(valid)],SINCE,UNTIL)
        self.assertEqual(result['statistics']['queues'],2)
        self.assertTrue(result['completeness']['complete'])
        alone=lzma.compress(line,format=lzma.FORMAT_ALONE)
        # The legacy header has no CRC: request a 128 MiB dictionary while
        # retaining a tiny body. Decoder must refuse before allocating it.
        hostile=self.root/'large-dictionary.lzma'
        hostile.write_bytes(alone[:1]+(128*1024*1024).to_bytes(4,'little')+alone[5:])
        limited=analyze_logs([str(hostile)],SINCE,UNTIL)
        self.assertFalse(limited['completeness']['complete'])
        self.assertIn('Memory usage limit',str(limited['sources'][0]['errors']))
    def test_compact_terminal_output_keeps_json_machine_only(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            code=cli.main(['--offline','--log',str(FIXTURE),'--since',SINCE.isoformat(),'--until',UNTIL.isoformat(),'--timezone','Asia/Dubai'])
        text=output.getvalue()
        self.assertEqual(code,0)
        self.assertNotIn('"returncode"',text)
        self.assertNotIn('"recognized_events"',text)
        self.assertIn('Saved 1',text)
        self.assertLess(len(text.splitlines()),25)
    def test_nonfinite_runtime_metadata_is_unknown_not_an_exception(self):
        self.write('/etc/hostname','box.example\n');self.write('/proc/uptime','nan 10\n');self.write('/proc/loadavg','inf 1 2\n')
        ctx=self.context();checks.platform_checks(ctx)
        self.assertEqual(next(f for f in ctx.findings if f['id']=='HOST.RUNTIME')['status'],'UNKNOWN')
    def test_policy_connection_warning_is_actionable_and_not_dropped(self):
        path=self.write('/policy.log','2026-11-03T10:30:00Z box postfix/smtpd[1]: warning: connect to 127.0.0.1:10023: Connection refused\n')
        result=analyze_logs([path],SINCE,UNTIL)
        self.assertIn('MAIL-DAEMON-ERROR',[f['id'] for f in result['findings']])
    def test_existing_report_fails_before_claiming_success(self):
        target=self.write('/report.json','original')
        output,error=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(output),contextlib.redirect_stderr(error):
            code=cli.main(['--offline','--log',str(FIXTURE),'--json','--report',target])
        self.assertEqual(code,3)
        self.assertEqual(output.getvalue(),'')
        self.assertEqual(Path(target).read_text(),'original')
    def test_whole_miab_doctor_profile_retains_real_uncertainty_without_false_alarms(self):
        self.write('/etc/os-release','ID=ubuntu\nVERSION_ID="22.04"\n')
        self.write('/etc/mailinabox.conf','PRIMARY_HOSTNAME=box.local.example\nSTORAGE_ROOT=/home/user-data\nPUBLIC_IP=203.0.113.10\n')
        self.write('/etc/hostname','box.local.example\n');self.write('/proc/uptime','1000 200\n');self.write('/proc/loadavg','0.1 0.2 0.3 1/20 1\n')
        self.write('/etc/resolv.conf','nameserver 127.0.0.1\n')
        self.write('/etc/postgrey/clients','partner.example\n')
        self.write('/home/user-data/backup/.fixture','no success marker')
        names=('postfix','dovecot','nginx','mailinabox','spampd','postgrey','spamassassin')
        responses={('systemctl','list-unit-files','--type=service','--no-legend','--no-pager'):Result(stdout=''.join(n+'.service '+('disabled' if n=='spamassassin' else 'enabled')+' enabled\n' for n in names)),('postqueue','-j'):Result(),('postconf','-P'):Result(),('postconf','-M'):Result(stdout='smtp inet n - n - - smtpd\n'),('systemctl','show','postgrey','--property=ExecStart','--value'):Result(stdout='/usr/sbin/postgrey --whitelist-clients=/etc/postgrey/clients'),('sshd','-T'):Result(stdout='port 22\npermitrootlogin prohibit-password\npasswordauthentication no\n'),('apt-mark','showhold'):Result(stdout='duplicity\n'),('dpkg-query','-W','-f=${Version}\n','duplicity'):Result(stdout='3.0.5.1-fixture\n'),('duplicity','--version'):Result(stdout='duplicity 3.0.5.1\n'),('dpkg-query','-W','-f=${db:Status-Abbrev}\n','unattended-upgrades'):Result(stdout='ii \n'),('ss','-ltnp'):Result(stdout='State Recv-Q Send-Q Local Address:Port Peer Address:Port\n')}
        for name in names:
            responses[('systemctl','show',name,'--property=LoadState,ActiveState,SubState','--value')]=Result(stdout='loaded\ninactive\ndead\n' if name=='spamassassin' else 'loaded\nactive\nrunning\n')
        for jail in ('postfix-sasl','dovecot','sshd','recidive'):
            responses[('fail2ban-client','status',jail)]=Result(stdout='Currently banned: 1\nCurrently failed: 2\n')
        for flag in ('-P','-Pi'):
            responses[('df',flag,'/','/home','/home/user-data')]=Result(stdout='Filesystem 1024-blocks Used Available Capacity Mounted on\n'+'/dev/root 100 10 90 10% /\n'*3)
        params={p:'' for p in checks._PARAMS};params.update(myhostname='box.local.example',mydomain='local.example',smtpd_relay_restrictions='permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination')
        responses.update({('postconf','-h',p):Result(stdout=v+'\n') for p,v in params.items()})
        args=cli.parser().parse_args(['--doctor','--timezone','Asia/Dubai']);args.root=str(self.root)
        report=cli.analyze(args,Fake(responses),SINCE,UNTIL,[str(FIXTURE)])
        failures=[f for f in report['findings'] if f['status'] in ('FAIL','WARN')]
        self.assertEqual(failures,[])
        self.assertTrue(report['completeness']['log_sources_complete'])
        self.assertFalse(report['completeness']['checks_complete'])  # actual backup-success evidence is absent
        self.assertEqual(report['active_probes'],[])
        output=io.StringIO()
        from mailradar.display import human
        with contextlib.redirect_stdout(output):
            human(report)
        self.assertNotIn('"returncode"',output.getvalue())
        self.assertIn('Последний успешный backup не подтверждён',output.getvalue())
    def test_journal_uses_instance_units_newest_first_and_pre_window_context(self):
        class JournalFake(Fake):
            def run(self,argv,timeout=8):
                self.history.append(argv)
                self_test.assertTrue(permitted(argv))
                return Result(stdout='2026-11-03T10:30:00.000000+0000 box postfix/qmgr[1]: ABCDE: removed\n')
        self_test=self
        runner=JournalFake();output=io.StringIO()
        with patch('mailradar.cli.Runner',return_value=runner),patch('mailradar.cli.default_logs',return_value=[]),contextlib.redirect_stdout(output):
            runner.close=lambda:None
            cli.main(['--flow','--journal','--json','--since',SINCE.isoformat(),'--until',UNTIL.isoformat()])
        command=runner.history[0]
        self.assertIn('--reverse',command);self.assertIn('postfix@*.service',command)
        self.assertEqual(command[command.index('--since')+1],'2026-11-02T10:00:00+00:00')
        self.assertEqual(json.loads(output.getvalue())['sources'][0]['path'],'journal:postfix,dovecot,postgrey')


@unittest.skipUnless(os.name=='posix','real PTY requires Linux')
class InteractiveMenuTests(unittest.TestCase):
    def setUp(self):
        import pty
        self.master,slave=pty.openpty()
        self.process=subprocess.Popen(['bash',str(ROOT/'mail-radar'),'--menu','--offline','--log',str(FIXTURE),'--since',SINCE.isoformat(),'--until',UNTIL.isoformat(),'--timezone','Asia/Dubai'],cwd=ROOT,stdin=slave,stdout=slave,stderr=slave)
        os.close(slave)
        self.buffer=b''
        self.addCleanup(self.cleanup)
    def cleanup(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=3)
        os.close(self.master)
    def until(self,text):
        import select
        end=time.monotonic()+10
        while text.encode() not in self.buffer:
            if time.monotonic()>end:
                self.fail('TTY prompt missing: '+text+'; '+self.buffer.decode(errors='replace'))
            ready,_,_=select.select([self.master],[],[],.1)
            if ready:
                try:
                    data=os.read(self.master,65536)
                except OSError:
                    self.fail('TTY closed: '+self.buffer.decode(errors='replace'))
                self.buffer+=data
        result,self.buffer=self.buffer,b''
        return result.decode(errors='replace')
    def send(self,text):
        os.write(self.master,text.encode())
    def test_two_menu_runs_and_quit_without_live_commands_or_json_dump(self):
        self.until('Номер [1]:')
        self.send('1\n')
        report=self.until('Enter — вернуться в меню; 0 — выход:')
        self.assertIn('Поток:',report)
        self.assertNotIn('"returncode"',report)
        self.assertNotIn('"time"',report)
        self.assertLess(len(report.splitlines()),35)
        self.send('\n');self.until('Номер [1]:')
        self.send('1\n');self.until('Enter — вернуться в меню; 0 — выход:')
        self.send('0\n')
        self.assertIn(self.process.wait(timeout=5),(0,1))
    def test_bad_menu_choice_reprompts_and_ctrl_c_has_no_traceback(self):
        self.until('Номер [1]:');self.send('bad\n')
        prompt=self.until('Номер [1]:')
        self.assertIn('Введите номер',prompt)
        self.process.send_signal(signal.SIGINT)
        self.assertEqual(self.process.wait(timeout=5),130)
    def test_menu_lists_headers_trace_and_post_update_probe_choice(self):
        menu=self.until('Номер [1]:')
        self.assertIn('Заголовки',menu)
        self.assertIn('Message-ID / Queue ID',menu)
        self.send('11\n')
        self.until('DNS/TLS/HTTP-пробы? [y/N]:')
        self.send('n\n');self.until('Enter — вернуться в меню; 0 — выход:')
        self.send('0\n');self.process.wait(timeout=5)


if __name__=='__main__':
    unittest.main()
