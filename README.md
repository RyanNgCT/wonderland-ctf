# wonderland-ctf
Writeups for the Forensics Challenge


**Mission**

A memory dump of a Windows machine is provided in the home directory of the root user. You have to use Volatility to analyze the memory dump and answer the following questions:

  1. What is the process number of the notepad process?
  2. A SIP VoIP client software was running on the machine. What is the IP address of the server that the client was hardcoded to use?
  3. The user working on the Windows machine was trying to do some shopping on amazon.com. Recover the email address and password of the user. (Flag is the password)
    
**Guidelines**

  * Volatility can be invoked by using vol.py command
  * Volatility is installed at /usr/local/volatility
  
## Step 1:
This was pretty straight forward. A simple Google search gave [this article](https://medium.com/@zemelusa/first-steps-to-volatile-memory-analysis-dcbd4d2d56a1). I first gathered information based on the memory dump. Here we are interested in the [suggested profiles](https://github.com/volatilityfoundation/volatility/wiki/2.6-Win-Profiles), which helps us conduct analysis based on specific plugins that Volatility already offers to help in the Forensic Investigation.
```
root@attackdefense:~# ls
memory_dump.mem
root@attackdefense:~# vol.py -f memory_dump.mem imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win10x64_10240_17770, Win10x64
                     AS Layer1 : SkipDuplicatesAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/root/memory_dump.mem)
                      PAE type : No PAE
                           DTB : 0x1aa000L
                          KDBG : 0xf80309398b20L
          Number of Processors : 2
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0xfffff803093f2000L
                KPCR for CPU 1 : 0xffffd0019db48000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2019-06-26 22:57:08 UTC+0000
     Image local date and time : 2019-06-27 04:27:08 +0530
```


Next, using the profile (Win10x64_10240_17770), we want to create a process dump of the programs loaded into memory.
```
root@attackdefense:~# vol.py -f memory_dump.mem --profile=Win10x64_10240_17770 pslist
Volatility Foundation Volatility Framework 2.6.1
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit                          
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0xffffe0019146b040 System                    4      0    124        0 ------      0 2019-06-26 17:49:28 UTC+0000                                 
0xffffe00193471040 smss.exe                312      4      2        0 ------      0 2019-06-26 17:49:28 UTC+0000                                 
0xffffe0019375a080 csrss.exe               392    380     10        0      0      0 2019-06-26 17:49:51 UTC+0000                                 
0xffffe001914a7080 wininit.exe             456    380      1        0      0      0 2019-06-26 17:49:52 UTC+0000                                 
0xffffe00193796480 csrss.exe               472    448     11        0      1      0 2019-06-26 17:49:52 UTC+0000                                 
0xffffe001939e2080 winlogon.exe            532    448      5        0      1      0 2019-06-26 17:49:53 UTC+0000                                 
0xffffe001914d1840 services.exe            572    456      5        0      0      0 2019-06-26 17:49:53 UTC+0000                                 
0xffffe00193a0c840 lsass.exe               584    456      6        0      0      0 2019-06-26 17:49:53 UTC+0000                                 
0xffffe00193a28840 svchost.exe             664    572     20        0      0      0 2019-06-26 17:49:55 UTC+0000                                 
0xffffe00193a2d840 svchost.exe             716    572     10        0      0      0 2019-06-26 17:49:55 UTC+0000                                 
0xffffe00193b4f840 dwm.exe                 824    532      9        0      1      0 2019-06-26 17:49:56 UTC+0000                                 
0xffffe00193b89840 svchost.exe             872    572     30        0      0      0 2019-06-26 17:49:56 UTC+0000                                 
0xffffe00193b9e840 svchost.exe             880    572     21        0      0      0 2019-06-26 17:49:56 UTC+0000                                 
0xffffe00193bd7840 svchost.exe             944    572     24        0      0      0 2019-06-26 17:49:56 UTC+0000                                 
0xffffe00193bdb840 svchost.exe             956    572     23        0      0      0 2019-06-26 17:49:56 UTC+0000                                 
0xffffe00193beb840 svchost.exe             980    572     18        0      0      0 2019-06-26 17:49:56 UTC+0000                                 
0xffffe00193bfa840 svchost.exe             988    572     66        0      0      0 2019-06-26 17:49:56 UTC+0000                                 
0xffffe00193c02080 WUDFHost.exe            764    880      8        0      0      0 2019-06-26 17:49:57 UTC+0000                                 
0xffffe00193cb0840 vmacthlp.exe           1040    572      1        0      0      0 2019-06-26 17:49:57 UTC+0000                                 
0xffffe00193d27840 dasHost.exe            1220    880      7        0      0      0 2019-06-26 17:49:58 UTC+0000                                 
0xffffe00192e3e840 spoolsv.exe            1616    572     12        0      0      0 2019-06-26 17:50:00 UTC+0000                                 
0xffffe00193ec9840 svchost.exe            1768    572     22        0      0      0 2019-06-26 17:50:02 UTC+0000                                 
0xffffe00193f29840 armsvc.exe             1980    572      2        0      0      1 2019-06-26 17:50:04 UTC+0000                                 
0xffffe00193f85840 svchost.exe            2016    572     11        0      0      0 2019-06-26 17:50:04 UTC+0000                                 
0xffffe00194011840 openvpnserv.ex         1516    572      2        0      0      0 2019-06-26 17:50:07 UTC+0000                                 
0xffffe0019405a840 svchost.exe            1968    572      6        0      0      0 2019-06-26 17:50:09 UTC+0000                                 
0xffffe0019403b080 ProtonVPNServi         2032    572      8        0      0      0 2019-06-26 17:50:09 UTC+0000                                 
0xffffe00194132840 svchost.exe            2172    572      7        0      0      0 2019-06-26 17:50:11 UTC+0000                                 
0xffffe0019416c840 VGAuthService.         2216    572      2        0      0      0 2019-06-26 17:50:11 UTC+0000                                 
0xffffe00194186840 vmtoolsd.exe           2260    572      9        0      0      0 2019-06-26 17:50:11 UTC+0000                                 
0xffffe00194264080 MsMpEng.exe            2384    572     25        0      0      0 2019-06-26 17:50:14 UTC+0000                                 
0xffffe001943d1840 WmiPrvSE.exe           2512    664     11        0      0      0 2019-06-26 17:50:16 UTC+0000                                 
0xffffe00191668080 dllhost.exe            2828    572     10        0      0      0 2019-06-26 17:50:20 UTC+0000                                 
0xffffe00193773080 msdtc.exe              2940    572      9        0      0      0 2019-06-26 17:50:22 UTC+0000                                 
0xffffe001943b1840 NisSrv.exe             2504    572     12        0      0      0 2019-06-26 17:50:31 UTC+0000                                 
0xffffe001943da840 MpCmdRun.exe           2472   2384      0 --------      0      0 2019-06-26 17:50:31 UTC+0000                                 
0xffffe0019477f840 SearchIndexer.         3656    572     18        0      0      0 2019-06-26 17:50:41 UTC+0000                                 
0xffffe00194811840 svchost.exe            3880    572      2        0      0      0 2019-06-26 17:50:49 UTC+0000                                 
0xffffe0019379a080 sihost.exe             4024    988     11        0      1      0 2019-06-26 17:50:51 UTC+0000                                 
0xffffe001948e9840 taskhostw.exe          4052    988      9        0      1      0 2019-06-26 17:50:51 UTC+0000                                 
0xffffe00194956080 userinit.exe           3192    532      0 --------      1      0 2019-06-26 17:50:52 UTC+0000                                 
0xffffe0019495b840 explorer.exe           3556   3192     72        0      1      0 2019-06-26 17:50:52 UTC+0000                                 
0xffffe00194918080 RuntimeBroker.         3704    664     12        0      1      0 2019-06-26 17:50:56 UTC+0000                                 
0xffffe00194b1c080 ShellExperienc         4500    664     63        0      1      0 2019-06-26 17:51:10 UTC+0000                                 
0xffffe00194e71080 InstallAgent.e         4884    664      1        0      1      0 2019-06-26 17:51:16 UTC+0000                                 
0xffffe00194397840 TabTip.exe             3876    880     11        0      1      0 2019-06-26 17:51:23 UTC+0000                                 
0xffffe001914712c0 TabTip32.exe           3592   3876      1        0      1      1 2019-06-26 17:51:24 UTC+0000                                 
0xffffe00195092840 vmtoolsd.exe           5532   3556      7        0      1      0 2019-06-26 17:51:33 UTC+0000                                 
0xffffe00195175840 WzPreloader.ex         5776   3556      5        0      1      0 2019-06-26 17:51:42 UTC+0000                                 
0xffffe00195159840 FAHWindow64.ex         5908   5888      2        0      1      0 2019-06-26 17:51:47 UTC+0000                                 
0xffffe001949cc080 openvpn-gui.ex         1064   3556      1        0      1      0 2019-06-26 17:51:53 UTC+0000                                 
0xffffe00194199080 svchost.exe            2060    572      1        0      1      0 2019-06-26 17:52:48 UTC+0000                                 
0xffffe00194eb7080 OneDrive.exe           1260    708     13        0      1      1 2019-06-26 17:53:30 UTC+0000                                 
0xffffe00194463840 jucheck.exe            3812   5228      0 --------      1      0 2019-06-26 17:57:07 UTC+0000                                 
0xffffe00194b82840 sppsvc.exe             5480    572      4        0      0      0 2019-06-26 18:04:48 UTC+0000                                 
0xffffe00195614840 SppExtComObj.E          156    664      1        0      0      0 2019-06-26 21:29:33 UTC+0000                                 
0xffffe001948d3840 microsip.exe           4284   3556     11        0      1      1 2019-06-26 21:55:39 UTC+0000
```
<pre><b>0xffffe0019570a380 notepad.exe            5376   3556      3        0      1      0 2019-06-26 21:58:42 UTC+0000</b></pre>
```
0xffffe00194606840 conhost.exe             364   4144      0 --------      1      0 2019-06-26 21:59:50 UTC+0000                                 
0xffffe00195115840 taskhostw.exe          5252    988      5        0      0      0 2019-06-26 22:07:33 UTC+0000                                 
0xffffe00193deb840 ngentask.exe           5928   5252      6        0      0      0 2019-06-26 22:07:34 UTC+0000                                 
0xffffe00191d4a080 conhost.exe            4836   5928      2        0      0      0 2019-06-26 22:07:34 UTC+0000                                 
0xffffe001940932c0 taskhostw.exe           412    988      4        0      1      0 2019-06-26 22:09:25 UTC+0000                                 
0xffffe00195199080 SearchProtocol         4448   3656      6        0      0      0 2019-06-26 22:54:37 UTC+0000                                 
0xffffe00191e0c840 firefox.exe            4756   4132      0 -------- ------      0 2019-06-26 22:54:49 UTC+0000                                 
0xffffe001951c0540 SearchFilterHo         5412   3656      1        0      0      0 2019-06-26 22:54:50 UTC+0000                                 
0xffffe00194de8840 SearchProtocol         1840   3656      4        0      1      0 2019-06-26 22:54:59 UTC+0000                                 
0xffffe00192545840 SearchUI.exe           3784    664     34        0      1      0 2019-06-26 22:55:02 UTC+0000
```
<pre><b>0xffffe001959e4380 firefox.exe            3236   5136     60        0      1      0 2019-06-26 22:55:42 UTC+0000
0xffffe00192959280 firefox.exe            3756   3236      9        0      1      0 2019-06-26 22:55:42 UTC+0000                                 
0xffffe00194196840 firefox.exe            3628   3236     23        0      1      0 2019-06-26 22:55:50 UTC+0000                                 
0xffffe001931b9840 firefox.exe            1164   3236     19        0      1      0 2019-06-26 22:55:50 UTC+0000                                 
0xffffe001937b3080 firefox.exe            4832   3236     23        0      1      0 2019-06-26 22:55:50 UTC+0000                                 
0xffffe0019593b080 firefox.exe             676   3236      0 --------      1      0 2019-06-26 22:55:52 UTC+0000                                 
0xffffe00195918080 firefox.exe            2288   3236     19        0      1      0 2019-06-26 22:56:02 UTC+0000</b></pre>
```
0xffffe00194e90840 audiodg.exe            5392    944      6        0      0      0 2019-06-26 22:57:02 UTC+0000                                 
0xffffe00194b10080 TabTip.exe             3516    880      0 --------      1      0 2019-06-26 22:57:04 UTC+0000                                 
0xffffe00193ada080 RamCapture64.e         3920   3556     10        0      1      0 2019-06-26 22:57:04 UTC+0000                                 
0xffffe00194269080 conhost.exe            1196   3920      9        0      1      0 2019-06-26 22:57:04 UTC+0000                                 
0xffffe001945c5080 ngen.exe               5772   5928      7        0      0      0 2019-06-26 22:57:07 UTC+0000                                 
0xffffe00193026080 mscorsvw.exe            976   5772      9        0      0      0 2019-06-26 22:57:08 UTC+0000                                 
0xffffe00194eba080                      24...0      0      0 -------- ------      0                                                              
0xffffe00194eba078                      393216      0      0 -------- ------      0 
```
Through observing the output, `notepad.exe` is found with the process id of `4284`.

## Step 2: 
A Google Search shows that SIP VOIP uses `microsip.exe`. We will need the process id of the program to create another smaller memory dump containing metadata and the data of that particular process.

I used `netscan` to determine if there was an ip address tagged to the protocol, unfortunately an ip of `*:*` was displayed, so I probably had to dig deeper.
```
root@attackdefense:~# vol.py -f memory_dump.mem --profile=Win10x64_10240_17770 netscan
Volatility Foundation Volatility Framework 2.6.1
Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0xe00191697ec0     UDPv4    0.0.0.0:58128                  *:*                                   4284     microsip.exe   2019-06-26 21:55:44 UTC+0000
0xe001918b4180     TCPv4    192.168.113.144:50652          34.194.72.9:443      ESTABLISHED      3236     firefox.exe    2019-06-26 22:56:37 UTC+0000
0xe001919e0990     TCPv4    127.0.0.1:50602                127.0.0.1:50601      ESTABLISHED      1164     firefox.exe    2019-06-26 22:55:52 UTC+0000
0xe00191c1ed10     TCPv4    192.168.113.144:50424          216.58.203.131:443   CLOSED           2477589352                2019-06-26 21:57:28 UTC+0000
0xe00191e3aa70     UDPv4    0.0.0.0:55702                  *:*                                   872      svchost.exe    2019-06-26 22:01:51 UTC+0000
0xe00191e3aa70     UDPv6    :::55702                       *:*                                   872      svchost.exe    2019-06-26 22:01:51 UTC+0000
0xe00192361010     TCPv4    192.168.113.144:50352          117.18.237.29:80     CLOSED           2477589352                2019-06-26 21:56:39 UTC+0000
0xe001929bed10     TCPv4    192.168.113.144:50667          13.35.128.128:443    CLOSED           3236     firefox.exe    2019-06-26 22:56:55 UTC+0000
0xe00192df3010     UDPv4    0.0.0.0:0                      *:*                                   872      svchost.exe    2019-06-26 22:57:08 UTC+0000
0xe00192df3010     UDPv6    :::0                           *:*                                   872      svchost.exe    2019-06-26 22:57:08 UTC+0000
0xe00192e469a0     UDPv4    0.0.0.0:0                      *:*                                   3236     firefox.exe    2019-06-26 22:58:05 UTC+0000
0xe00192eb0800     TCPv4    127.0.0.1:50603                127.0.0.1:50604      ESTABLISHED      3628     firefox.exe    2019-06-26 22:55:52 UTC+0000
0xe00192ef8800     TCPv4    127.0.0.1:50601                127.0.0.1:50602      ESTABLISHED      1164     firefox.exe    2019-06-26 22:55:52 UTC+0000
0xe00192f34a50     UDPv4    0.0.0.0:3702                   *:*                                   1220     dasHost.exe    2019-06-26 22:57:48 UTC+0000
0xe00192f34a50     UDPv6    :::3702                        *:*                                   1220     dasHost.exe    2019-06-26 22:57:48 UTC+0000
0xe00192f37560     TCPv4    192.168.113.144:50351          117.18.237.29:80     CLOSED           2477589352                2019-06-26 21:56:39 UTC+0000
0xe0019318a700     UDPv4    0.0.0.0:5355                   *:*                                   872      svchost.exe    2019-06-26 22:57:09 UTC+0000
0xe001931e2840     TCPv4    127.0.0.1:50600                127.0.0.1:50599      ESTABLISHED      3236     firefox.exe    2019-06-26 22:55:42 UTC+0000
0xe001934d17a0     UDPv4    192.168.113.144:1900           *:*                                   980      svchost.exe    2019-06-26 21:29:36 UTC+0000
0xe00193502880     UDPv4    0.0.0.0:55646                  *:*                                   872      svchost.exe    2019-06-26 22:56:55 UTC+0000
0xe00193502880     UDPv6    :::55646                       *:*                                   872      svchost.exe    2019-06-26 22:56:55 UTC+0000
0xe001935702d0     TCPv4    0.0.0.0:49411                  0.0.0.0:0            LISTENING        1616     spoolsv.exe    2019-06-26 17:50:02 UTC+0000
0xe001935702d0     TCPv6    :::49411                       :::0                 LISTENING        1616     spoolsv.exe    2019-06-26 17:50:02 UTC+0000
0xe001935b37d0     UDPv4    0.0.0.0:53151                  *:*                                   872      svchost.exe    2019-06-26 22:56:52 UTC+0000
0xe001935b37d0     UDPv6    :::53151                       *:*                                   872      svchost.exe    2019-06-26 22:56:52 UTC+0000
0xe00193688320     TCPv4    192.168.113.144:50554          40.90.189.152:443    ESTABLISHED      3556     explorer.exe   2019-06-26 22:52:56 UTC+0000
0xe00193689490     TCPv4    127.0.0.1:50637                127.0.0.1:50636      ESTABLISHED      2288     firefox.exe    2019-06-26 22:56:11 UTC+0000
0xe001939934e0     TCPv4    192.168.113.144:50656          52.89.38.17:443      ESTABLISHED      3236     firefox.exe    2019-06-26 22:56:49 UTC+0000
0xe001939ff260     UDPv4    0.0.0.0:5355                   *:*                                   872      svchost.exe    2019-06-26 22:57:08 UTC+0000
0xe001939ff260     UDPv6    :::5355                        *:*                                   872      svchost.exe    2019-06-26 22:57:08 UTC+0000
0xe00193a043e0     TCPv4    0.0.0.0:49412                  0.0.0.0:0            LISTENING        584      lsass.exe      2019-06-26 17:50:05 UTC+0000
0xe00193a86ec0     UDPv6    fe80::8d7d:7bb2:4ef5:7dc6:49361 *:*                                   980      svchost.exe    2019-06-26 21:29:36 UTC+0000
0xe00193a739a0     TCPv4    0.0.0.0:49411                  0.0.0.0:0            LISTENING        1616     spoolsv.exe    2019-06-26 17:50:02 UTC+0000
0xe00193b257f0     TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        716      svchost.exe    2019-06-26 17:49:55 UTC+0000
0xe00193b28c00     TCPv4    0.0.0.0:49408                  0.0.0.0:0            LISTENING        456      wininit.exe    2019-06-26 17:49:55 UTC+0000
0xe00193b28c00     TCPv6    :::49408                       :::0                 LISTENING        456      wininit.exe    2019-06-26 17:49:55 UTC+0000
0xe00193b2e900     TCPv4    0.0.0.0:135                    0.0.0.0:0            LISTENING        716      svchost.exe    2019-06-26 17:49:55 UTC+0000
0xe00193b2e900     TCPv6    :::135                         :::0                 LISTENING        716      svchost.exe    2019-06-26 17:49:55 UTC+0000
0xe00193b3d580     TCPv4    0.0.0.0:49408                  0.0.0.0:0            LISTENING        456      wininit.exe    2019-06-26 17:49:55 UTC+0000
0xe00193ce1d50     TCPv4    0.0.0.0:49409                  0.0.0.0:0            LISTENING        944      svchost.exe    2019-06-26 17:49:58 UTC+0000
0xe00193ce1d50     TCPv6    :::49409                       :::0                 LISTENING        944      svchost.exe    2019-06-26 17:49:58 UTC+0000
0xe00193d29010     TCPv4    0.0.0.0:49410                  0.0.0.0:0            LISTENING        988      svchost.exe    2019-06-26 17:49:59 UTC+0000
0xe00193d2c710     TCPv4    0.0.0.0:49410                  0.0.0.0:0            LISTENING        988      svchost.exe    2019-06-26 17:49:59 UTC+0000
0xe00193d2c710     TCPv6    :::49410                       :::0                 LISTENING        988      svchost.exe    2019-06-26 17:49:59 UTC+0000
0xe00193dafec0     UDPv4    0.0.0.0:5353                   *:*                                   872      svchost.exe    2019-06-26 22:57:09 UTC+0000
0xe00193df8510     UDPv4    0.0.0.0:61227                  *:*                                   872      svchost.exe    2019-06-26 22:57:33 UTC+0000
0xe00193df8510     UDPv6    :::61227                       *:*                                   872      svchost.exe    2019-06-26 22:57:33 UTC+0000
0xe00193ec92c0     UDPv4    0.0.0.0:52597                  *:*                                   872      svchost.exe    2019-06-26 22:57:33 UTC+0000
0xe00193ec92c0     UDPv6    :::52597                       *:*                                   872      svchost.exe    2019-06-26 22:57:33 UTC+0000
0xe00193f2e3a0     UDPv6    fe80::8d7d:7bb2:4ef5:7dc6:546  *:*                                   944      svchost.exe    2019-06-26 22:55:09 UTC+0000
0xe00193ea33c0     TCPv4    192.168.113.144:50657          52.89.38.17:443      ESTABLISHED      3236     firefox.exe    2019-06-26 22:56:49 UTC+0000
0xe00193f743e0     UDPv4    0.0.0.0:4500                   *:*                                   988      svchost.exe    2019-06-26 17:50:05 UTC+0000
0xe00193f743e0     UDPv6    :::4500                        *:*                                   988      svchost.exe    2019-06-26 17:50:05 UTC+0000
0xe00193f83cf0     UDPv4    0.0.0.0:500                    *:*                                   988      svchost.exe    2019-06-26 17:50:05 UTC+0000
0xe00193fa5b80     UDPv4    0.0.0.0:4500                   *:*                                   988      svchost.exe    2019-06-26 17:50:05 UTC+0000
0xe00193fa7a40     UDPv4    0.0.0.0:500                    *:*                                   988      svchost.exe    2019-06-26 17:50:05 UTC+0000
0xe00193fa7a40     UDPv6    :::500                         *:*                                   988      svchost.exe    2019-06-26 17:50:05 UTC+0000
0xe00193fa8cf0     UDPv4    0.0.0.0:0                      *:*                                   988      svchost.exe    2019-06-26 17:50:05 UTC+0000
0xe00193fd08c0     TCPv4    0.0.0.0:49412                  0.0.0.0:0            LISTENING        584      lsass.exe      2019-06-26 17:50:05 UTC+0000
0xe00193fd08c0     TCPv6    :::49412                       :::0                 LISTENING        584      lsass.exe      2019-06-26 17:50:05 UTC+0000
0xe00194008d70     UDPv4    0.0.0.0:0                      *:*                                   988      svchost.exe    2019-06-26 17:50:07 UTC+0000
0xe00194008d70     UDPv6    :::0                           *:*                                   988      svchost.exe    2019-06-26 17:50:07 UTC+0000
0xe0019406da60     UDPv4    0.0.0.0:0                      *:*                                   988      svchost.exe    2019-06-26 17:50:42 UTC+0000
0xe001940ae1b0     TCPv4    192.168.113.144:50653          13.35.130.40:443     ESTABLISHED      3236     firefox.exe    2019-06-26 22:56:40 UTC+0000
0xe001940bb9e0     TCPv4    -:50669                        -:443                ESTABLISHED      3236     firefox.exe    2019-06-26 22:57:33 UTC+0000
0xe001940e94e0     TCPv4    0.0.0.0:445                    0.0.0.0:0            LISTENING        4        System         2019-06-26 17:50:09 UTC+0000
0xe001940e94e0     TCPv6    :::445                         :::0                 LISTENING        4        System         2019-06-26 17:50:09 UTC+0000
0xe00194228370     TCPv4    192.168.113.144:50655          52.89.38.17:443      ESTABLISHED      3236     firefox.exe    2019-06-26 22:56:49 UTC+0000
0xe001942521d0     TCPv4    0.0.0.0:49409                  0.0.0.0:0            LISTENING        944      svchost.exe    2019-06-26 17:49:58 UTC+0000
0xe00194451d50     UDPv4    192.168.113.144:138            *:*                                   4        System         2019-06-26 21:29:39 UTC+0000
0xe001945d5970     UDPv4    0.0.0.0:3702                   *:*                                   1220     dasHost.exe    2019-06-26 22:57:48 UTC+0000
0xe00194717c50     TCPv4    0.0.0.0:7680                   0.0.0.0:0            LISTENING        988      svchost.exe    2019-06-26 17:50:39 UTC+0000
0xe00194717c50     TCPv6    :::7680                        :::0                 LISTENING        988      svchost.exe    2019-06-26 17:50:39 UTC+0000
0xe0019478c590     UDPv4    0.0.0.0:60782                  *:*                                   1220     dasHost.exe    2019-06-26 22:50:28 UTC+0000
0xe0019478c590     UDPv6    :::60782                       *:*                                   1220     dasHost.exe    2019-06-26 22:50:28 UTC+0000
0xe00194727440     TCPv4    0.0.0.0:49426                  0.0.0.0:0            LISTENING        572      services.exe   2019-06-26 17:50:39 UTC+0000
0xe00194727440     TCPv6    :::49426                       :::0                 LISTENING        572      services.exe   2019-06-26 17:50:39 UTC+0000
0xe00194727700     TCPv4    0.0.0.0:49426                  0.0.0.0:0            LISTENING        572      services.exe   2019-06-26 17:50:39 UTC+0000
0xe00194728b00     TCPv4    192.168.113.144:50666          13.35.134.162:443    ESTABLISHED      3236     firefox.exe    2019-06-26 22:56:55 UTC+0000
0xe0019486e400     UDPv4    0.0.0.0:0                      *:*                                   3236     firefox.exe    2019-06-26 22:57:20 UTC+0000
0xe0019486e400     UDPv6    :::0                           *:*                                   3236     firefox.exe    2019-06-26 22:57:20 UTC+0000
0xe001948eb940     UDPv4    0.0.0.0:3702                   *:*                                   1220     dasHost.exe    2019-06-26 22:57:09 UTC+0000
0xe001948eb940     UDPv6    :::3702                        *:*                                   1220     dasHost.exe    2019-06-26 22:57:09 UTC+0000
0xe00194936720     UDPv4    192.168.113.144:51377          *:*                                   988      svchost.exe    2019-06-26 21:29:36 UTC+0000
0xe001949be380     TCPv4    127.0.0.1:50604                127.0.0.1:50603      ESTABLISHED      3628     firefox.exe    2019-06-26 22:55:52 UTC+0000
0xe00194ba0ec0     UDPv4    0.0.0.0:0                      *:*                                   3236     firefox.exe    2019-06-26 22:57:20 UTC+0000
0xe00194bd0d50     UDPv4    192.168.113.144:137            *:*                                   4        System         2019-06-26 21:29:39 UTC+0000
0xe00194bf02b0     TCPv4    192.168.113.144:50665          13.35.128.128:443    ESTABLISHED      3236     firefox.exe    2019-06-26 22:56:55 UTC+0000
0xe00194dfa510     TCPv4    192.168.113.144:50654          13.35.130.42:443     ESTABLISHED      3236     firefox.exe    2019-06-26 22:56:40 UTC+0000
0xe00194f258b0     TCPv4    127.0.0.1:50609                127.0.0.1:50608      ESTABLISHED      4832     firefox.exe    2019-06-26 22:55:54 UTC+0000
0xe00195044390     UDPv4    0.0.0.0:0                      *:*                                   872      svchost.exe    2019-06-26 22:57:47 UTC+0000
0xe00195044390     UDPv6    :::0                           *:*                                   872      svchost.exe    2019-06-26 22:57:47 UTC+0000
0xe001950479d0     UDPv4    0.0.0.0:0                      *:*                                   3236     firefox.exe    2019-06-26 22:58:06 UTC+0000
0xe001950479d0     UDPv6    :::0                           *:*                                   3236     firefox.exe    2019-06-26 22:58:06 UTC+0000
0xe001950562c0     UDPv4    0.0.0.0:5355                   *:*                                   872      svchost.exe    2019-06-26 22:57:09 UTC+0000
0xe001950562c0     UDPv6    :::5355                        *:*                                   872      svchost.exe    2019-06-26 22:57:09 UTC+0000
0xe00195131010     UDPv4    0.0.0.0:5355                   *:*                                   872      svchost.exe    2019-06-26 22:57:48 UTC+0000
0xe00195131010     UDPv6    :::5355                        *:*                                   872      svchost.exe    2019-06-26 22:57:48 UTC+0000
0xe0019513bd10     TCPv4    192.168.113.144:50610          34.209.158.104:443   ESTABLISHED      3236     firefox.exe    2019-06-26 22:55:54 UTC+0000
0xe00195222d50     UDPv4    0.0.0.0:51215                  *:*                                   872      svchost.exe    2019-06-26 22:57:20 UTC+0000
0xe00195222d50     UDPv6    :::51215                       *:*                                   872      svchost.exe    2019-06-26 22:57:20 UTC+0000
0xe00195242940     UDPv4    0.0.0.0:5355                   *:*                                   872      svchost.exe    2019-06-26 22:57:47 UTC+0000
0xe001952a9010     UDPv4    0.0.0.0:60781                  *:*                                   1220     dasHost.exe    2019-06-26 22:50:28 UTC+0000
0xe00195390ec0     UDPv4    0.0.0.0:61366                  *:*                                   872      svchost.exe    2019-06-26 22:57:33 UTC+0000
0xe00195390ec0     UDPv6    :::61366                       *:*                                   872      svchost.exe    2019-06-26 22:57:33 UTC+0000
0xe001954bd880     UDPv4    0.0.0.0:59389                  *:*                                   872      svchost.exe    2019-06-26 22:57:08 UTC+0000
0xe001954bd880     UDPv6    :::59389                       *:*                                   872      svchost.exe    2019-06-26 22:57:08 UTC+0000
0xe001956bbbe0     TCPv4    0.0.0.0:50335                  0.0.0.0:0            LISTENING        4284     microsip.exe   2019-06-26 21:55:44 UTC+0000
0xe0019572b010     UDPv4    127.0.0.1:49364                *:*                                   980      svchost.exe    2019-06-26 21:29:36 UTC+0000
0xe00195763ec0     UDPv4    192.168.113.144:49363          *:*                                   980      svchost.exe    2019-06-26 21:29:36 UTC+0000
0xe001957914d0     UDPv4    0.0.0.0:54931                  *:*                                   872      svchost.exe    2019-06-26 21:56:41 UTC+0000
0xe001957914d0     UDPv6    :::54931                       *:*                                   872      svchost.exe    2019-06-26 21:56:41 UTC+0000
0xe0019579b9c0     UDPv4    0.0.0.0:5353                   *:*                                   872      svchost.exe    2019-06-26 22:57:47 UTC+0000
0xe0019579b9c0     UDPv6    :::5353                        *:*                                   872      svchost.exe    2019-06-26 22:57:47 UTC+0000
0xe001957e5350     UDPv4    0.0.0.0:5353                   *:*                                   872      svchost.exe    2019-06-26 22:56:32 UTC+0000
0xe001957e5350     UDPv6    :::5353                        *:*                                   872      svchost.exe    2019-06-26 22:56:32 UTC+0000
0xe00195880d10     TCPv4    192.168.113.144:50659          52.89.38.17:443      CLOSED           3236     firefox.exe    2019-06-26 22:56:49 UTC+0000
0xe0019588eec0     UDPv4    127.0.0.1:1900                 *:*                                   980      svchost.exe    2019-06-26 21:29:36 UTC+0000
0xe001958a0010     UDPv4    0.0.0.0:0                      *:*                                   3236     firefox.exe    2019-06-26 22:57:33 UTC+0000
0xe001958a0010     UDPv6    :::0                           *:*                                   3236     firefox.exe    2019-06-26 22:57:33 UTC+0000
0xe001958cf810     UDPv4    0.0.0.0:0                      *:*                                   3236     firefox.exe    2019-06-26 22:58:06 UTC+0000
0xe00195916ba0     TCPv4    192.168.113.144:50664          23.195.74.27:80      ESTABLISHED      3236     firefox.exe    2019-06-26 22:56:52 UTC+0000
0xe0019593da20     UDPv4    0.0.0.0:5355                   *:*                                   872      svchost.exe    2019-06-26 22:57:08 UTC+0000
0xe00195963a50     TCPv4    192.168.113.144:50661          117.18.237.29:80     ESTABLISHED      3236     firefox.exe    2019-06-26 22:56:49 UTC+0000
0xe001959f1d10     TCPv4    192.168.113.144:50439          54.65.120.202:443    CLOSED           2477589352                2019-06-26 21:57:39 UTC+0000
0xe00195acab90     UDPv6    fe80::8d7d:7bb2:4ef5:7dc6:1900 *:*                                   980      svchost.exe    2019-06-26 21:29:36 UTC+0000
0xe00195afaa70     TCPv4    127.0.0.1:50599                127.0.0.1:50600      ESTABLISHED      3236     firefox.exe    2019-06-26 22:55:42 UTC+0000
0xe00195affba0     TCPv4    192.168.113.144:50662          117.18.237.29:80     ESTABLISHED      3236     firefox.exe    2019-06-26 22:56:49 UTC+0000
0xe00195b531c0     UDPv4    0.0.0.0:0                      *:*                                   3236     firefox.exe    2019-06-26 22:57:33 UTC+0000
0xe00195b531c0     UDPv6    :::0                           *:*                                   3236     firefox.exe    2019-06-26 22:57:33 UTC+0000
0xe00195b56500     TCPv4    192.168.113.144:50663          117.18.237.29:80     ESTABLISHED      3236     firefox.exe    2019-06-26 22:56:49 UTC+0000
0xe00195b65ec0     UDPv4    0.0.0.0:0                      *:*                                   3236     firefox.exe    2019-06-26 22:57:33 UTC+0000
0xe00195b65ec0     UDPv6    :::0                           *:*                                   3236     firefox.exe    2019-06-26 22:57:33 UTC+0000
0xe00195baf8c0     UDPv4    0.0.0.0:51893                  *:*                                   872      svchost.exe    2019-06-26 22:58:05 UTC+0000
0xe00195baf8c0     UDPv6    :::51893                       *:*                                   872      svchost.exe    2019-06-26 22:58:05 UTC+0000
0xe00195c28ec0     TCPv4    192.168.113.144:139            0.0.0.0:0            LISTENING        4        System         2019-06-26 21:29:39 UTC+0000
0xe00195c2d9c0     UDPv4    0.0.0.0:3544                   *:*                                   988      svchost.exe    2019-06-26 21:29:36 UTC+0000
0xe00195c34ec0     UDPv4    0.0.0.0:0                      *:*                                   3236     firefox.exe    2019-06-26 22:57:33 UTC+0000
0xe00195c34ec0     UDPv6    :::0                           *:*                                   3236     firefox.exe    2019-06-26 22:57:33 UTC+0000
0xe00195c31180     TCPv4    127.0.0.1:50608                127.0.0.1:50609      ESTABLISHED      4832     firefox.exe    2019-06-26 22:55:54 UTC+0000
0xe00195c359b0     TCPv4    127.0.0.1:50636                127.0.0.1:50637      ESTABLISHED      2288     firefox.exe    2019-06-26 22:56:11 UTC+0000
0xe00195c7bbe0     TCPv4    0.0.0.0:50334                  0.0.0.0:0            LISTENING        4284     microsip.exe   2019-06-26 21:55:44 UTC+0000
0xe00195cd87a0     UDPv6    ::1:49362                      *:*                                   980      svchost.exe    2019-06-26 21:29:36 UTC+0000
0xe00195ce3ec0     UDPv6    ::1:1900                       *:*                                   980      svchost.exe    2019-06-26 21:29:36 UTC+0000
0xe00195ce4010     UDPv6    fe80::b0:e910:3571:b4b8:546    *:*                                   944      svchost.exe    2019-06-26 22:56:44 UTC+0000
0xe00195d38d10     TCPv4    192.168.113.144:50668          172.217.27.202:443   ESTABLISHED      3236     firefox.exe    2019-06-26 22:57:20 UTC+0000
0xe00195d68570     UDPv4    0.0.0.0:65265                  *:*                                   872      svchost.exe    2019-06-26 22:57:09 UTC+0000
0xe00195d68570     UDPv6    :::65265                       *:*                                   872      svchost.exe    2019-06-26 22:57:09 UTC+0000
0xe00195daeb10     TCPv4    192.168.113.144:50356          34.210.151.118:443   CLOSED           2477589352                2019-06-26 21:56:41 UTC+0000
0xe00195db7d10     TCPv4    192.168.113.144:50516          40.90.23.215:443     CLOSED           988      svchost.exe    2019-06-26 22:09:26 UTC+0000
0xe00195dc32d0     UDPv4    0.0.0.0:0                      *:*                                   956      svchost.exe    2019-06-26 22:57:09 UTC+0000
0xe00195dc32d0     UDPv6    :::0                           *:*                                   956      svchost.exe    2019-06-26 22:57:09 UTC+0000
```

Thereafter, I got the idea from the same article to use `memdump`, which enables FIs to analyse the memory contents of executables.
```
root@attackdefense:~# vol.py -f memory_dump.mem --profile=Win10x64_10240_17770 memdump -p 4284 --dump-dir .
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
Writing microsip.exe [  4284] to 4284.dmp
```

This allows us to use the `strings` command to analyse the dump file for leads. Unfortunately, it is too big when passed without arguments and we need to filter the output using the `grep` command. 

My initial thought process was to use regex to filter out the target IP address since it was most likely in the dump with the following syntax:

`root@attackdefense:~#strings 4284.dmp | grep -Fi "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"`

Unfortunately, this did not give any output. Thereafter I searched for details on the SIP protocol and found that the port was [commonly specified after the SIP proxy](https://www.microsip.org/help).

> Mainly used for dialing or sending dual tones (DTMF). Various input formats are supported.
Example: 1-800-567-46-57, 1234, 1234@sip.server.com, 1234@sip.server.com:5043, 192.168.0.55.

Based on this the substring `:port` seemed like a viable filter.

```
root@attackdefense:~# strings 4284.dmp | grep -Fi ":port"
78.216.50.84":port=8080
Extension:Port:Disconnect
[FUNCTION] %s :PortReset Failed at port %d subport %d
[FUNCTION] %s :port %d subport %d.
[FUNCTION] %s :Port %d has been plug out
[FUNCTION] %s :Port %d Link status  DET %x
[FUNCTION] %s :Port %d Link status  DET %x successful
[FUNCTION] %s :Port %d ,PxIS %lx Px->IS %lx Px->SERR %lx cmd %x TFD %x ERR %x
[FUNCTION] %s :Port %d subport %d,PxIS %lx Px->IS %lx Px->SERR %lx cmd %x TFD %x ERR %x
```

Unfortunately, the ip address `78.216.50.84` from the search was incorrect. Someone gave me a hint that the IP address of the callee could be (e.g. `sip: 192.168.x.x`) so I decided to try that out and sure enough I managed to recover the IP address of the server!
```
root@attackdefense:~# strings 4284.dmp | grep -Fi "sip:"
...
To: <sip:1111@192.168.10.129>
...
```
In the strings the `To` field was specified so that was the server's IP address: `192.168.10.129`.

## Step 3: 
This was pretty much an extension of step 2, just that the process id was different and the search string needed to be changed. Since the user was using a gmail account on `amazon.com` and there was no presence of a client application, the most likely application used to conduct this activity was `firefox.exe`, with process number `3236`.
```
root@attackdefense:~# vol.py -f memory_dump.mem --profile=Win10x64_10240_17770 memdump -p 3236 --dump-dir .
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
Writing firefox.exe [  3236] to 3236.dmp
```
I wrote the executable to the dump file again, similar to the steps taken above and then thereafter proceeded to search the dump file for the password. I identified a few keywords for this section--`email`, `password`, `amazon.com`. Using several search strings, I could not find a password field.
```
strings 3236.dmp | grep -Fi "password"
strings 3236.dmp | grep -Fi "amazon.com"
strings 3236.dmp | grep -Fi "password\|amazon.com.*amazon.com\|password"
```

Searching for emails with gmail's "signature" also proved futile:

`strings 3236.dmp | grep -Fi "@gmail.com"`

This resulted in a bunch of emails that in my opinion, served as a "distraction" and changing the search term to the particular email did not yield results/leads moving forward.

Finally, I chanced upon [this article](https://security.stackexchange.com/questions/85980/how-to-find-passwords-in-memory-password-managers), which suggested using `&Password` since it is common in URL encoding.
```
root@attackdefense:~# strings 3236.dmp | grep -Fi "&Password"
9tulPaSkxFFKaUnL41P9XwtpMYAAN-4jAqpE9CNWoKJsyiBOG63Gw5J_d4bCfeRbF9xCAf2JFcxZqwmM2BTXXPuclHi0.TDLuTEFn1YpOVWeH1OFCoA&email=target_user%40gmail.com&create=0&password=test_password&metadata1=ECdITeCs%3AZY%2BFmhJxsdk9GZfBP4oKTY4X54qTTLzmabBVOB8u%2FOwfF6ZjDEudP4zwqTzZ1pvgXwSeC3Q7239UojWUODl8l74KqaP9%2F8gmASqL0OXncogWX8EPRAPk1QyNxQ6jEsAo1S0MQtl%2F0SKtkpOkpTU98Iz7jpcXmvtOuHr5lEixhfYHcygO1QvLcMCK%2FF0q7%2FbKv60kYyH4Czqi3jTkPBt0lk39s4UTFHxVbYW8HgWXyP1QoOI1WupXb6e5XKvXw0hkwxSAbiEdcW%2B3W7fxZuV0uBS1G7mMITo2c6CvN8MAYjHL2xbNZdoEgHhgV%2BGqi693%2FBOFrv1WdHv4ZWGaH6AUdjaDqM3QXUSA%2FBDn9jn%2Fu2CttChq2Mx5rjFaP0On95VSFD8HehhI5a%2F7wRE7wv81ECpEKSQmySIFd%2FKooWFD5ZuKVpRap3r9ZTbBi5v%2B%2FnavOPvvR%2BIWT6bS2jhpYQ%2B5gncaWmp%2Bs3MBeeHMtv2qnsWLvxBMGDXnfeJEJPO62ooxR4AnCUJ4zZoGrNYotDl23TzJsK1CXL60vNZQz2bNTmONRWIcviW1aipawqSWCkdoCj2wg6iUqLZkXXPE8t8V%2BP9Vlir7fP%2Fyg2vGiGXyLsYgM4aw9JHAnX4sa88XfdAwW
```
The password for user `target_user@gmail.com` is `test_password`.

---
I'm greatful for this experience, which was my first ever individual CTF where I solved the challenge pretty much by myself aside from a few hints 😅. May this be the first of many to come!
