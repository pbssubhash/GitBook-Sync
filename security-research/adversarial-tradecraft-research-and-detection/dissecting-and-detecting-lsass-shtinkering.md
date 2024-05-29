# Dissecting & Detecting Lsass Shtinkering

There was a recent attack vector to dump credentials from LSASS.exe (ab)using Windows Error Reporting.&#x20;

_**Link to Presentation:**_ [DefCon Media Presentation](https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Asaf%20Gilboa%20-%20LSASS%20Shtinkering%20Abusing%20Windows%20Error%20Reporting%20to%20Dump%20LSASS.pdf)

_**Link to Video:**_ [Abusing Windows Error Reporting to dump LSASS](https://www.youtube.com/watch?v=-QRr\_8pvOiY)

## What?

We all know that once a user logins, the credentials are stored in the memory and to be specific, in LSASS's process memory. This memory was read and credential was stolen by tools like Mimikatz. More recently, newer techniques to dump the memory have emerged. Several techniques like procdump, task manager, comsvcs (using Minidump) are already present and are seen exploited in the wild.&#x20;

This is a newer technique to create a dump of `lsass.exe` using Windows Error Reporting.&#x20;

{% hint style="danger" %}
At the time of writing (December 2022), this technique is not detected by Multiple top security products. It's advisible to leverage the detections present in the detection section to protect your organisation.&#x20;
{% endhint %}

## How?

While the video is a supreme source of understanding how the entire process works, here's a quick summary of the same:&#x20;

* Whenever a process crashes, it can initiate a dump creation using `WerFault.exe`, an inbuilt utility in Windows. The command line for such a dumping event would be something like this: `WeFault.exe -u -p <process_id>`
* However, to create LSASS's dump, either LSASS need to send a signal through LPC to Windows Error Reporting that there's a problem, create a dump or a malicious process can do that abusing the functionality in Windows Error Reporting through LPC.&#x20;
* The author of the presentation has exactly done the second one where he successfully created a POC which would send an LPC to Windows Error Reporting to create a dump of Lsass.exe.

### Pre-requisites for the attack:

*   Privileged User (NT AUTHORITY\SYSTEM)&#x20;

    If you have an administrative access, you can get it using the following command

```
PsExec.exe -i -s cmd.exe
```

* The user mode dumping has be enabled by creating a registry key at `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDump`; Key: DumpType and Value: 2 \[DWORD]; The same can be done using the command:&#x20;

{% code overflow="wrap" %}
```
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" /v DumpType /d 2
```
{% endcode %}

### The Exploit:&#x20;

* Download the source code: [https://github.com/deepinstinct/Lsass-Shtinkering](https://github.com/deepinstinct/Lsass-Shtinkering)&#x20;
* Compile source code&#x20;
* Create a command prompt with NT AUTHORITY\SYSTEM and run the executable

## How to detect?

Here's how the attack is logged on my detection lab.&#x20;

<figure><img src="../../.gitbook/assets/WhatsApp Image 2022-12-07 at 21.14.47 (1).jpg" alt=""><figcaption><p>Simulation of LSASS Shtinkering</p></figcaption></figure>

When observed carefully, the following things stood out:&#x20;

* _**Registry value is created**_&#x20;
  * Can be detected using Sysmon (Registry Event) or EDR's telemetry or Windows Security Process Command Line (if Command line logging is enabled)&#x20;
* _**Malicious process spawns `WerFault.exe`**_ with the parameters `-u -p <lsass_process_id> -ip <malicious_process_id> -s 244 (unknown)`
  * Can be detected by monitoring Process Events through Windows Security log or Sysmon or EDR Telemetry
* **A dump file** is created at `C:\Windows\System32\config\systemprofile\AppData\Local\CrashDumps\`&#x20;
  * Can be detected using File Write events either through Sysmon or EDR Telemetry

For detecting the registry key "DumpType" 's value to 2, here's a Microsoft Defender for Endpoint (MDE) query:&#x20;

{% code title="lsass_shtinkering_reg.kql" overflow="wrap" %}
```kusto
DeviceRegistryEvents | where (ActionType == "RegistryValueSet" and RegistryKey == "\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\DumpType" or RegistryKey == "\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\lsass.exe\DumpType" and ActionType == "SetValue")
```
{% endcode %}

For detecting the Windows Error Reporting being triggered to dump `lsass.exe`, here's an MDE query:&#x20;

{% code title="lsass_shtinkering_proc.kql" overflow="wrap" %}
```kusto
DeviceProcessEvents 
| where ((((FolderPath endswith @'\Werfault.exe') or (InitiatingProcessVersionInfoOriginalFileName =~ @'WerFault.exe') or (ProcessVersionInfoOriginalFileName =~ @'WerFault.exe')) and ((ParentUser contains @'AUTHORI' or ParentUser contains @'AUTORI') and (((AccountUpn contains @'AUTHORI' or AccountUpn contains @'AUTORI')) or ((AccountName contains @'AUTHORI' or AccountName contains @'AUTORI'))) and (ProcessCommandLine contains @' -u -p ' and ProcessCommandLine contains @' -ip ' and ProcessCommandLine contains @' -s '))) and ((InitiatingProcessFolderPath !~ @'C:\Windows\System32\lsass.exe')))

```
{% endcode %}

For detecting the `lsass.dmp` being created, here's an MDE query:&#x20;

{% code title="lsass_shtinkering_file.kql" overflow="wrap" %}
```kusto
DeviceFileEvents 
| where (FolderPath startswith @'C:\Windows\System32\config\systemprofile\AppData\Local\CrashDumps\' and FolderPath contains @'lsass.exe.' and FolderPath endswith @'.dmp')
```
{% endcode %}

For the generic sigma signature (for converting this into any format you'd like, check this: [https://github.com/SigmaHQ/sigma/pull/3764/files](https://github.com/SigmaHQ/sigma/pull/3764/files)&#x20;
