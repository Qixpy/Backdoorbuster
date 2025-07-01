/*
BackdoorBuster YARA Rules
Malware detection signatures for common backdoors and threats
*/

rule Suspicious_Backdoor_Strings
{
    meta:
        description = "Detects common backdoor strings"
        author = "BackdoorBuster"
        date = "2024-01-01"
        severity = "high"

    strings:
        $backdoor1 = "nc.exe -l -p"
        $backdoor2 = "cmd.exe /c"
        $backdoor3 = "powershell.exe -ep bypass"
        $backdoor4 = "CreateRemoteThread"
        $backdoor5 = "VirtualAllocEx"
        $backdoor6 = "WriteProcessMemory"
        $backdoor7 = "SetWindowsHookEx"
        $backdoor8 = "keylogger"
        $backdoor9 = "password stealer"
        $backdoor10 = "reverse shell"

    condition:
        any of them
}

rule Suspicious_Network_Activity
{
    meta:
        description = "Detects suspicious network-related strings"
        author = "BackdoorBuster"
        severity = "medium"

    strings:
        $net1 = "connect back"
        $net2 = "bind shell"
        $net3 = "download and execute"
        $net4 = "http://" nocase
        $net5 = "https://" nocase
        $net6 = "ftp://" nocase
        $net7 = "telnet"
        $net8 = "ssh"

    condition:
        2 of them
}

rule Suspicious_File_Operations
{
    meta:
        description = "Detects suspicious file operations"
        author = "BackdoorBuster"
        severity = "medium"

    strings:
        $file1 = "DeleteFile"
        $file2 = "MoveFile"
        $file3 = "CopyFile"
        $file4 = "CreateFile"
        $file5 = "WriteFile"
        $file6 = "ReadFile"
        $file7 = "temp\\"
        $file8 = "\\system32\\"
        $file9 = "\\windows\\"

    condition:
        3 of them
}

rule Potential_Rootkit
{
    meta:
        description = "Detects potential rootkit behavior"
        author = "BackdoorBuster"
        severity = "high"

    strings:
        $rootkit1 = "ZwQuerySystemInformation"
        $rootkit2 = "NtQuerySystemInformation"
        $rootkit3 = "KeServiceDescriptorTable"
        $rootkit4 = "SSDT"
        $rootkit5 = "unhook"
        $rootkit6 = "stealth"
        $rootkit7 = "hide process"
        $rootkit8 = "hide file"

    condition:
        any of them
}

rule Suspicious_Registry_Operations
{
    meta:
        description = "Detects suspicious registry operations"
        author = "BackdoorBuster"
        severity = "medium"

    strings:
        $reg1 = "RegOpenKey"
        $reg2 = "RegSetValue"
        $reg3 = "RegDeleteKey"
        $reg4 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        $reg5 = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        $reg6 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        $reg7 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"

    condition:
        2 of them
}

rule Encryption_Ransomware
{
    meta:
        description = "Detects potential ransomware encryption"
        author = "BackdoorBuster"
        severity = "critical"

    strings:
        $encrypt1 = "CryptEncrypt"
        $encrypt2 = "CryptDecrypt"
        $encrypt3 = "AES"
        $encrypt4 = "RSA"
        $encrypt5 = "encrypt"
        $encrypt6 = "decrypt"
        $ransom1 = "ransom"
        $ransom2 = "payment"
        $ransom3 = "bitcoin"
        $ransom4 = "your files have been encrypted"

    condition:
        (2 of ($encrypt*)) and (1 of ($ransom*))
}

rule Process_Injection
{
    meta:
        description = "Detects process injection techniques"
        author = "BackdoorBuster"
        severity = "high"

    strings:
        $inject1 = "CreateRemoteThread"
        $inject2 = "WriteProcessMemory"
        $inject3 = "VirtualAllocEx"
        $inject4 = "OpenProcess"
        $inject5 = "QueueUserAPC"
        $inject6 = "SetThreadContext"
        $inject7 = "ResumeThread"
        $inject8 = "NtCreateThreadEx"

    condition:
        3 of them
}

rule Suspicious_Imports
{
    meta:
        description = "Detects suspicious API imports"
        author = "BackdoorBuster"
        severity = "medium"

    strings:
        $api1 = "LoadLibrary"
        $api2 = "GetProcAddress"
        $api3 = "VirtualAlloc"
        $api4 = "VirtualProtect"
        $api5 = "CreateThread"
        $api6 = "ExitThread"
        $api7 = "TerminateProcess"
        $api8 = "ShellExecute"

    condition:
        4 of them
}

rule Obfuscated_Code
{
    meta:
        description = "Detects potentially obfuscated code"
        author = "BackdoorBuster"
        severity = "medium"

    strings:
        $obfus1 = { 90 90 90 90 90 }  // NOP sled
        $obfus2 = { CC CC CC CC CC }  // INT3 padding
        $obfus3 = "xor"
        $obfus4 = "base64"
        $obfus5 = "decode"
        $obfus6 = "deobfus"

    condition:
        any of them
}

rule Suspicious_Persistence
{
    meta:
        description = "Detects persistence mechanisms"
        author = "BackdoorBuster"
        severity = "high"

    strings:
        $persist1 = "schtasks"
        $persist2 = "at.exe"
        $persist3 = "sc.exe"
        $persist4 = "wmic"
        $persist5 = "service"
        $persist6 = "startup"
        $persist7 = "autorun"
        $persist8 = "scheduled task"

    condition:
        2 of them
}
