rule Detect_WMI_Usage {
  meta:
    description = "Обнаружение использование Windows Management Instrumentation (WMI)"

  strings:
    $wmi1  = "Get-WMIObject" nocase ascii
    $wmi2  = "Invoke-WmiMethod" nocase ascii
    $wmi3  = "wmiclass" nocase ascii
    $wmi4  = "Win32_Process" nocase ascii
    $wmi6  = "root\\CIMV2" nocase ascii
    $wmi7  = "ManagementObjectSearcher" nocase ascii
    $wmi8  = "ManagementObject" nocase ascii
    $wmi9  = "SWbemServices" nocase ascii
    $wmi10 = "wmic.exe" nocase ascii
    $wmi11 = "scrobj.dll" nocase ascii

  condition:
    any of ($wmi*)
}

rule Empire_Invoke_Mimikatz_Gen {
  meta:
    description = "Обнаружение компонента Empire Invoke-Mimikatz.ps1"

  strings:
    $s1 = "= \"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQ" ascii
    $s2 = "Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, \"Void\", 0, \"\", $ExeArgs)" fullword ascii

  condition:
    (uint16(0) == 0x7566 and filesize < 4000KB and 1 of them) or all of them
}

rule Detect_Potential_SMB_Usage {
  meta:
    description = "Обнаружены артефакты потенциального использования протокола SMB"

  strings:
    $c = "\\c$\\" ascii wide nocase

  condition:
    $c
}

rule Using_System_Process {
  meta:
    description = "Обнаружение использования легитимных системных процессов для выполнения вредоносного кода"

  strings:
    $ = "rundll32.exe" ascii nocase wide
    $ = "smss.exe" ascii nocase wide
    $ = "csrss.exe" ascii nocase wide
    $ = "wininit.exe" ascii nocase wide
    $ = "services.exe" ascii nocase wide
    $ = "lsass.exe" ascii nocase wide
    $ = "svchost.exe" ascii nocase wide
    $ = "explorer.exe" ascii nocase wide
    $ = "taskhostw.exe" ascii nocase wide
    $ = "ctfmon.exe" ascii nocase wide
    $ = "winlogon.exe" ascii nocase wide
    $ = "dwm.exe" ascii nocase wide
    $ = "spoolsv.exe" ascii nocase wide
    $ = "sihost.exe" ascii nocase wide
    $ = "RuntimeBroker.exe" ascii nocase wide
    $ = "ApplicationFrameHost.exe" ascii nocase wide

  condition:
    any of them
}

rule Detect_PowerShell_Commands {
  meta:
    description = "Обнаружение запуска PowerShell-команд"

  strings:
    $powershell      = "powershell" ascii nocase wide
    $noexit          = "noexit" ascii nocase wide
    $executionpolicy = "ExecutionPolicy" ascii nocase wide
    $noprofile       = "noprofile" ascii nocase wide
    $command         = "command" ascii nocase wide
    $encoded         = "EncodedCommand" ascii nocase wide
    $invoke_command  = "invoke-command" ascii nocase wide
    $scriptblock     = "scriptblock" ascii nocase wide
    $iex             = "Invoke-Expression" ascii nocase wide
    $authman         = "AuthorizationManager" ascii nocase wide

  condition:
    any of them
}

rule Detect_an_executable_file_or_a_system_command {
  meta:
    description = "Обнаружение запуска исполняемых файлов или системных команд"

  strings:
    $ = "vbNormal" ascii nocase wide
    $ = "vbNormalFocus" ascii nocase wide
    $ = "vbHide" ascii nocase wide
    $ = "vbMinimizedFocus" ascii nocase wide
    $ = "vbMaximizedFocus" ascii nocase wide
    $ = "vbNormalNoFocus" ascii nocase wide
    $ = "vbMinimizedNoFocus" ascii nocase wide
    $ = "WScript.Shell" ascii nocase wide
    $ = "ShellExecute" ascii nocase wide
    $ = "ShellExecuteA" ascii nocase wide
    $ = "shell32" ascii nocase wide
    $ = "InvokeVerb" ascii nocase wide
    $ = "InvokeVerbEx" ascii nocase wide

  condition:
    any of them
}

rule Detect_Code_Injection_Into_Another_Process {
  meta:
    description = "Обнаружение внедрения кода в другой процесс"

  strings:
    $createthread       = "CreateThread" ascii nocase wide
    $createuserthread   = "CreateUserThread" ascii nocase wide
    $virtualalloc       = "VirtualAlloc" ascii nocase wide
    $virtualallocex     = "VirtualAllocEx" ascii nocase wide
    $rtlmovememory      = "RtlMoveMemory" ascii nocase wide
    $writeprocessmemory = "WriteProcessMemory" ascii nocase wide
    $setcontextthread   = "SetContextThread" ascii nocase wide
    $queueapcthread     = "QueueApcThread" ascii nocase wide
    $writevirtualmemory = "WriteVirtualMemory" ascii nocase wide
    $virtualprotect     = "VirtualProtect" ascii nocase wide

  condition:
    any of them
}

rule Potential_Obfuscation_Strings {
  meta:
    description = "Обнаружение возможной попытки обфускации строк"

  strings:
    $chr        = "Chr" ascii nocase wide fullword
    $char       = "char" ascii nocase wide fullword
    $chrb       = "ChrB" ascii nocase wide
    $ps_e       = "powershell -e" ascii nocase wide
    $fromBase   = "FromBase" ascii nocase wide
    $chrw       = "ChrW" ascii nocase wide
    $strreverse = "StrReverse" ascii nocase wide
    $xor        = "Xor" ascii nocase wide fullword

  condition:
    any of them
}


rule Detect_Potential_Persistence_Startup {
  meta:
    description = "Обнаружение попытки закрепления в папке автозагрузки Windows"

  strings:
    $ = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii nocase wide
    $ = "Start Menu\\Programs\\Startup" ascii nocase wide

  condition:
    any of them
}


rule Detect_Potential_Persistence_Run_Registry {
  meta:
    description = "Обнаружение попытки закрепления через реестр Run/RunOnce"

  strings:
    $ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase wide
    $ = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii nocase wide

  condition:
    any of them
}

rule Detect_Potential_Persistence_ScheduledTasks {
  meta:
    description = "Обнаружение попытки закрепления через планировщик заданий"

  strings:
    $ = "schtasks /create" ascii nocase wide
    $ = "schtasks.exe /create" ascii nocase wide

  condition:
    any of them
}

rule Detect_Potential_Persistence_WindowsService {
  meta:
    description = "Обнаружение попытки закрепления через сервисы Windows"

  strings:
    $ = "sc create" ascii nocase wide
    $ = "sc.exe create" ascii nocase wide
    $ = "New-Service" ascii nocase wide // PowerShell

  condition:
    any of them
}
