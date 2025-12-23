
rule SuspiciousStrings {
    meta:
        description = "Detects suspicious strings commonly found in malware"
    strings:
        $s1 = "cmd.exe"
        $s2 = "powershell.exe"
        $s3 = "CreateProcess"
        $s4 = "VirtualAlloc"
        $s5 = "WriteProcessMemory"
        $s6 = "SetWindowsHookEx"
        $s7 = "keylogger"
        $s8 = "backdoor"
    condition:
        any of ($s*)
}

rule NetworkActivity {
    meta:
        description = "Detects network-related suspicious activity"
    strings:
        $n1 = "socket"
        $n2 = "connect"
        $n3 = "send"
        $n4 = "recv"
        $n5 = "WSAStartup"
        $n6 = "InternetOpen"
    condition:
        3 of ($n*)
}

rule Encryption {
    meta:
        description = "Detects encryption-related functions"
    strings:
        $c1 = "CryptEncrypt"
        $c2 = "CryptDecrypt"
        $c3 = "CryptGenKey"
        $c4 = "AES"
        $c5 = "RSA"
    condition:
        any of ($c*)
}
