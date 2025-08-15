rule meterpreter_reverse_tcp_shellcode {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Rule for metasploit's  meterpreter reverse tcp raw shellcode"

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s3 = { 4c77 2607 }             // kernel32 checksum
        $s4 = "ws2_"                    // ws2_32.dll
        $s5 = { 2980 6b00 }             // WSAStartUp checksum
        $s6 = { ea0f dfe0 }             // WSASocket checksum
        $s7 = { 99a5 7461 }             // connect checksum

    condition:
        all of them and filesize < 5KB
}

rule meterpreter_reverse_tcp_shellcode_Linux {
    meta:
        author = "Anon"
        description = "Rule for metasploit's  meterpreter reverse tcp raw shellcode Linux"

    strings:
        $s1 = { 6a0a 5e31 dbf7 e353 4353 6a }     // shellcode prologe in metasploit

    condition:
        all of them and filesize < 5KB
}

//  Extracted from main:
//
//  4011ec:       48 89 45 f8             mov    %rax,-0x8(%rbp)
//  4011f0:       31 c0                   xor    %eax,%eax
//  4011f2:       b8 00 00 00 00          mov    $0x0,%eax
//  4011f7:       e8 ba ff ff ff          call   4011b6 <func>
//  4011fc:       bf 00 00 00 00          mov    $0x0,%edi
//  401201:       e8 aa fe ff ff          call   4010b0 <time@plt>
//  401206:       89 c6                   mov    %eax,%esi
//  401208:       48 8d 05 07 0e 00 00    lea    0xe07(%rip),%rax 
rule payload_example_linux {
    meta:
        author = "Anon"
        description = "Example Malware Linux payload"

    strings:
        $s1 = { 48 89 45 f8 31 c0 b8 00 00 00 00 e8 ba ff ff ff bf 00 00 00 00 e8 aa fe ff ff }

    condition:
        all of them and filesize < 5MB
}

// Extracted fomr main
//
//  401130:       50                      push   %rax
//  401131:       b8 ef be ad de          mov    $0xdeadbeef,%eax
//  401136:       48 89 04 24             mov    %rax,(%rsp)
//  40113a:       48 bf 04 20 40 00 00    movabs $0x402004,%rdi
//  401141:       00 00 00
//  401144:       48 83 c7 04             add    $0x4,%rdi
//  401148:       e8 e3 fe ff ff          call   401030 <puts@plt>
//  40114d:       31 c0                   xor    %eax,%eax
//  40114f:       59                      pop    %rcx
//  401150:       c3                      ret
rule payload_example_linux_2 {
    meta:
        author = "Anon"
        description = "Example Malware Linux payload"

    strings:
        $s1 = { b8 ef be ad de 48 89 04 24 48 bf 04 20 40 00 00 00 00 00}

    condition:
        all of them and filesize < 5MB
}

rule meterpreter_reverse_tcp_elf_Linux {
    meta:
        author = "Anon"
        description = "Rule for metasploit's  meterpreter reverse tcp elf Linux"

    strings:
        $s1 = { 6a 09 58 99 b6 10 48 89 d6 4d 31 }     // elf prologe in metasploit

    condition:
        all of them and filesize < 5KB
}

rule buthi_ransomware_Linux {
    meta:
        author = "Anon"
        description = "Rule for Buthi Ransomware Linux"

    strings:
        $s1 = { 0fb6 1401 84d2 75e6 488d 5001 eb02 31d2 4889 5424 }     // loading ransom note in memory

    condition:
        all of them
}

rule gafgyt_botnet_Linux {
    meta:
        author = "Anon"
        description = "Rule for gafgyt botnet Linux"

    strings:
        $s1 = { bed8 be40 00b8 0000 }     // initial socket connection

    condition:
        all of them
}

rule meterpreter_reverse_tcp_shellcode_rev1 {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Meterpreter reverse TCP shell rev1"
        LHOST = 0xae
        LPORT = 0xb5

    strings:
        $s1 = { 6a00 53ff d5 }

    condition:
        meterpreter_reverse_tcp_shellcode and $s1 in (270..filesize)
}

rule meterpreter_reverse_tcp_shellcode_rev2 {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Meterpreter reverse TCP shell rev2"
        LHOST = 194
        LPORT = 201

    strings:
        $s1 = { 75ec c3 }

    condition:
        meterpreter_reverse_tcp_shellcode and $s1 in (270..filesize)
}

rule meterpreter_reverse_tcp_shellcode_domain {
    meta:
        author = "FDD @ Cuckoo sandbox"
        description = "Variant used if the user specifies a domain instead of a hard-coded IP"

    strings:
        $s1 = { a928 3480 }             // Checksum for gethostbyname
        $domain = /(\w+\.)+\w{2,6}/

    condition:
        meterpreter_reverse_tcp_shellcode and all of them
}

rule metasploit_download_exec_shellcode_rev1 {
    meta:
        author = "FDD @ Cuckoo Sandbox"
        description = "Rule for metasploit's download and exec shellcode"
        name = "Metasploit download & exec payload"
        URL = 185

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s4 = { 4c77 2607 }             // checksum for LoadLibraryA
        $s5 = { 3a56 79a7 }             // checksum for InternetOpenA
        $s6 = { 5789 9fc6 }             // checksum for InternetConnectA
        $s7 = { eb55 2e3b }             // checksum for HTTPOpenRequestA
        $s8 = { 7546 9e86 }             // checksum for InternetSetOptionA
        $s9 = { 2d06 187b }             // checksum for HTTPSendRequestA
        $url = /\/[\w_\-\.]+/

    condition:
        all of them and filesize < 5KB
}

rule metasploit_download_exec_shellcode_rev2 {
    meta:
        author = "FDD @ Cuckoo Sandbox"
        description = "Rule for metasploit's download and exec shellcode"
        name = "Metasploit download & exec payload"
        URL = 185

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s4 = { 4c77 2607 }             // checksum for LoadLibraryA
        $s5 = { 3a56 79a7 }             // checksum for InternetOpenA
        $s6 = { 5789 9fc6 }             // checksum for InternetConnectA
        $s7 = { eb55 2e3b }             // checksum for HTTPOpenRequestA
        $s9 = { 2d06 187b }             // checksum for HTTPSendRequestA
        $url = /\/[\w_\-\.]+/

    condition:
        all of them and filesize < 5KB
}

rule metasploit_bind_shell {
    meta:
        author = "FDD @ Cuckoo Sandbox"
        description = "Rule for metasploit's bind shell shellcode"
        name = "Metasploit bind shell payload"

    strings:
        $s1 = { fce8 8?00 0000 60 }     // shellcode prologe in metasploit
        $s2 = { 648b ??30 }             // mov edx, fs:[???+0x30]
        $s3 = { 4c77 2607 }             // checksum for LoadLibraryA
        $s4 = { 2980 6b00 }             // checksum for WSAStartup
        $s5 = { ea0f dfe0 }             // checksum for WSASocketA
        $s6 = { c2db 3767 }             // checksum for bind
        $s7 = { b7e9 38ff }             // checksum for listen
        $s8 = { 74ec 3be1 }             // checksum for accept

    condition:
        all of them and filesize < 5KB
}
