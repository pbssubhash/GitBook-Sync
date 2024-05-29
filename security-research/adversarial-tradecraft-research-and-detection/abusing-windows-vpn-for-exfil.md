# Abusing Windows VPN for EXFIL

Recently, I came across a section in Windows settings called "VPN Settings". After some digging, I identified that we can "create", "modify" existing VPN settings and "connect" to newly created VPNs.&#x20;

Obviously, VPNs are used for circumventing network controls. This can be abused to exfiltrate data or create a pivot into network. The following is a small blog post which outlines attack techniques for abusing this Windows VPN feature for Red Team engagements.&#x20;

> Goes without saying, whatever's published is only intended for educational purposes and I'm not responsible for any malicious usage. _**I'm adding few detection controls at the bottom for our defender friends to start monitoring their network.**_

![VPN Settings page](<../../.gitbook/assets/image (42).png>)

Ok, So there's a VPN setting pane inside Windows. Here's how you can access:

1. Head to Settings > Network & Internet
2. Choose ‘VPN’ from the left pane
3. Click ‘Add a VPN connection’ from the screen that appears

{% embed url="https://www.techadvisor.com/how-to/vpn/windows-10-built-in-vpn-3804720" %}
Windows 10 Built In VPN
{% endembed %}

The weird thing is that any "non-administrative" users can create a VPN profile, connect to it. Essentially this means that any user can create a VPN without having administrative privilege. This means that user can bypass proxy/firewall and perform c00l actions like: establish tunnel with a server \[thereby creating a pivot into the network], exfiltrate huge amounts of data and many more.&#x20;

How to do it?&#x20;

Step 1:&#x20;

1. Create a PPTP VPN Server by following the guide below (takes 2 minutes)

{% embed url="https://help.ubuntu.com/community/PPTPServer" %}

2\. Create a VPN connection using the settings pane

![](<../../.gitbook/assets/image (52).png>)

3\. Connect to the connection

![](<../../.gitbook/assets/image (58).png>)

### Exfiltration

Once you are connected, you can do a lot. For instance, using "uploadserver" \[Python package] to upload data.&#x20;

On your VPN server, type:

```
pip3 install uploadserver
python3 -m uploadserver
```

Go to your VPN connected computer and use the local URL:

![](<../../.gitbook/assets/image (34).png>)



Does it work through PowerShell for non-administrative users?

No.

![](<../../.gitbook/assets/image (33).png>)

_However, you can use "rasdial.exe" to connect via command line. This can be used to trigger the VPN (which maybe set through compromised RDP) or set it using persistence methods like startup folders to repeatedly connect to the VPN._&#x20;

![](<../../.gitbook/assets/image (40).png>)



## Detection

Event ID: "20222" is created in Application log whenever a user connects to a VPN.&#x20;

![](<../../.gitbook/assets/image (43).png>)

_**The Server Address contains the server that's being used.**_&#x20;



_**Update: I've observed in few setups that although we are able to add a new VPN, I'm unable to connect to it (Not sure which control is blocking it). Drop a note if you know something about it.**_

Peace&#x20;

./[@pbssubhash](https://twitter.com/pbssubhash)
