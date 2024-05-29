---
description: >-
  The blog post presents a take on EDR Silencer, a hack tool that was open
  sourced. It also throws light on how it works and how to detect.
---

# EDR Silencer - Embracing the Silence

EDR Silencer is a very interesting tool. It was open sourced on [GitHub](https://github.com/netero1010/EDRSilencer). The functionality was previously created in Night Hawk, a C2 framework that's sold by MDSec Labs.&#x20;

## 🤔How does it work?

In the world of connected EDRs/XDRs, if the machine isn't connected to the Internet, much of the functionality of these solutions are essentially dead. Things like reporting threats that are identified, getting threat intelligence, providing access to telemetry on the machine, etc. are non-usable. Interesting enough, this also hampers response capabilities as functionality such as "RTR" (CrowdStrike) & "Live Response" (Microsoft Defender for Endpoint) won't work.&#x20;

The idea behind this offensive tool is to utilize Windows Filtering platform, an inbuilt utility (set of system services) available in Windows Vista 7 and later to block EDRs from communicating to the Internet.&#x20;

Windows Filtering Platform was intended to be used by security programs such as Firewalls or Antimalware software, etc. However, just with any other legitimate feature, Humans leave no stone unturned to abuse these features. :joy:

The tool iterates through the list of current processes, if it matches with a list of predefined secrurity executable names, it adds the process (along with the full path) to the list for further processesing. In the end, it adds all the identified processes to Windows Filtering Platform's block list which effectively blocks it from communicating to it's mother ship :vulcan:

## 🔐How to detect?

The following are few techniques that you can use to detect the tool and/or usage of this tool in your environment.&#x20;

### ⏩ 1. Command Line Parameters (Not Recommended)

The following modes are available in the tool:&#x20;

```javascript
EDRSilencer.exe blockedr //Created WFP rules for all identified EDRs
EDRSilencer.exe unblockall //Deletes all the rules
EDRSilencer.exe unblock <filter id> //Deletes a specific filter 
EDRSilencer.exe block <full path> //Creates a rule for a specific process.
```

<figure><img src="../../.gitbook/assets/image (72).png" alt=""><figcaption><p>Example command line</p></figcaption></figure>

The following queries can be used to detect activity which leverages hardcoded GUIDs.

**Kibana Query:**

{% code overflow="wrap" fullWidth="false" %}
```sql
process.command_line.text: "blockedr" and winlog.event_id: 4688
```
{% endcode %}

**Kusto Query:**

{% code overflow="wrap" %}
```javascript
Event
| where EventID == 4688
| where RenderedDescription has_any("blockedr")
```
{% endcode %}

The above queries only leverage `blockedr` only because the other command line parameters are known to generate noise as they're likely to be used for other benign programs (since they're very simple terms)

### ⏩ 2.  WFP Policy change - Event log (Recommended)

By default, there's no log generated when a new program is added to Windows filtering platform. However, with a simple tweaking, it's possible to generate limited telemetry related to this activity. The logging can be created using _Group policy editor_ > _Security Settings_ > _Advanced Audit Policy Configuration_ > _System Audit Policy_ > _Policy Change_ > _Audit Filtering Platform Policy Change._

Alternatively, the following auditpol command can be used to enable auditing. AuditPol isn't natively available on Windows. You can download it from [here](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol).

{% code overflow="wrap" %}
```javascript
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (29).png" alt=""><figcaption><p>Audit Policy</p></figcaption></figure>

When this is enabled, several types of events are generated. A very interesting event ID: 5441 is generated every time when the Windows Filtering Platform is reloaded (typically when restarted). These rules contain the list of executables added to the block list. However the format is a bit skewed and can't be used to write rules directly. See for yourself.

<figure><img src="../../.gitbook/assets/image (31).png" alt=""><figcaption><p>Event Log Entry</p></figcaption></figure>

{% hint style="warning" %}
It's important to understand that the event is generated only after the reload of WFP (typically a reboot) and an attacker will have an advantage with respect to time. Events won't be generated if the system isn't restarted!

Plus, if an attacker enables the rules > perform malicious action > unblock the ports, the detection will fail.
{% endhint %}

The following queries can be used to detect activity using the above-mentioned event IDs.&#x20;

**Kibana Query:**

{% code overflow="wrap" %}
```json
message:("d78e1e87-8644-4ea5-9437-d809ecefc971" OR "c38d57d1-05a7-4c33-904f-7fbceee60e82" OR "4a72393b-319f-44bc-84c3-ba54dcb3b6b4") and winlog.event_id:"5441" and message: "Custom Outbound Filter"
```
{% endcode %}

**Kusto Query:**

```java
Event
| where EventID == 5441
| where EventData has "s.m.p.e.n.g...e"
```

The above query covers Microsoft defender rule being created. Similar logic can be created for the respective EDRs. As I get access to other EDRs for testing, I'll update this.

Below is a snippet indicating a sample Event ID.

### ⏩ 3.  Hardcoded GUIDs and Names (Not Recommended)

Interestingly, the author has hardcoded the GUIDs for Layer, Filter and Filter Name in the code. These are reflected in event logs (when the requisite policy is enabled) and the system has rebooted post the attack.

However, as corrected by Chris (the author of the tool), the GUIDs are default GUIDs that are given by Microsoft. Hence using the filter name to detect&#x20;

<figure><img src="../../.gitbook/assets/image (28).png" alt=""><figcaption><p>Hardcoded GUIDs</p></figcaption></figure>

The following queries can be used to detect activity which leverages hardcoded GUIDs.

**Kibana Query:**

{% code overflow="wrap" fullWidth="false" %}
```sql
message:("Custom Outbound Filter") and winlog.event_id:"5441"
```
{% endcode %}

**Kusto Query:**

{% code overflow="wrap" %}
```javascript
Event
| where EventID == "5441"
| where EventData has_any ("Custom Outbound Filter")
```
{% endcode %}

<figure><img src="../../.gitbook/assets/image (24).png" alt=""><figcaption><p>Detection using hardcoded GUIDs.</p></figcaption></figure>

{% hint style="warning" %}
This detection technique has to be used with caution as it's pretty easy to change the hardcoded values and recompile to evade this technique.
{% endhint %}

### ⏩ 4.  Presence of this tool using Yara (Recommended)

Finally, to detect the tool, we can use the following Yara rule. This tool can be used along with your own security tool (many major EDRs provide way to use Yara) or [OsQuery](https://osquery.readthedocs.io/en/stable/deployment/yara/) or Yara[ | GitHub](https://github.com/VirusTotal/yara/releases/tag/v4.3.2) to scan files on the system.

<pre class="language-css" data-overflow="wrap"><code class="lang-css">import "pe"
rule edr_silencer_hacktool {
    meta:
        author = "Subhash Popuri &#x3C;@pbssubhash>"
        filetype = "Executable"
<strong>        description = "Detects EDR Silencer tool, that's used to essentially supress communication between EDR agent and it's server"
</strong>        date = "01/03/2024"
        version = "1.0"
    strings:
        $a1 = "SeDebugPrivilege" fullword ascii 
        $a2 = "FwpmEngineClose0" fullword ascii
        $a3 = "FwpmEngineClose0" fullword ascii
	$edr1 = "MsMpEng.exe" fullword ascii
	$edr2 = "MsSense.exe" fullword ascii
	$edr3 = "SenseIR.exe" fullword ascii
	$edr4 = "SenseNdr.exe" fullword ascii
	$edr5 = "SenseNdr.exe" fullword ascii
	$edr6 = "SenseCncProxy.exe" fullword ascii
	$edr7 = "elastic-agent.exe" fullword ascii
	$edr8 = "elastic-endpoint.exe" fullword ascii
    condition:
        pe.is_pe and all of ($a*) and all of ($edr*)
}
</code></pre>

{% hint style="warning" %}
It's important to understand that it's fairly easy to modify an executable to evade Yara rule. Usage of packers (or sophisticated loaders) can be used to achieve the same. However, in many cases these are robust enough to stop lazy adversaries.
{% endhint %}

This, along with other rules that I've created can be accessed here: [Blue Sig | GitHub](https://github.com/pbssubhash/Blue-Sig/).

### ⏩ 5. Windows Filtering Platform blocking a connection.

Windows provides an Event log entry for every time a connection was blocked due to an existing rule. For more information, please check this: [Event ID 5157](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5157). However, this event is known to be extremely noisy and is not recommended. Hence, use it at your own risk and only after prior testing as this would do more harm than good by overwriting important events.

<figure><img src="../../.gitbook/assets/image (75).png" alt=""><figcaption><p>Image taken from Microsoft's documentation.</p></figcaption></figure>

## 💀 Variants in the wild

So far 2 variants of the same tool were identified in the wild, uploaded to Virus Total. The page might be updated with future instances of identification.

**Hashes of identified files:**

* 3b2de5c23a09cee3661dd8f499d43ca5275159c64bd567cfcc133aceac5b2573
* 08d7aa59bd14b270d8d0a7a757d796248dae7a8ce2f82a8dc7a3b882ff4170a9
* c9b25e4425550d311d41de08e254c55945d4b0ec3206192d5c0454c3926e3d43

<figure><img src="../../.gitbook/assets/image (74).png" alt=""><figcaption></figcaption></figure>

## 🤘Final Thoughts

EDR Silencer seems to be a very interesting hack tool. If my hunch is correct, we'll see more of this technique, many more variants of the same tool in sophisticated attacks.

If you see something wrong or if you feel there's a better implementation of the same or have general feedback, please reach out to me - [LinkedIn](https://in.linkedin.com/in/pbssubhash) or [Twitter](https://twitter.com/pbssubhash). I'd be more than happy to take constructive criticism or any feedback that comes my way. It'll help me learn, grow and contribute to the community.
