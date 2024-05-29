---
description: >-
  TL;DR; In a recent incident, Nobelium (APT-29) used a HTML dropper to download
  a file and store it on the disk;
---

# Analyzing Nobelium's HTML Dropper - EnvyScout

Recently, I got my hands on a malware sample used by Nobelium / APT29 and wanted to use this opportunity to learn and revise my malware analysis skills :smile:&#x20;

Please review my work and provide feedback at my n00b-ish attempt at Malware analysis :smile:

## Analysis Summary:&#x20;

* _\[ASSUMPTION] Attacker sends a malicious HTML file or a link to the victim_&#x20;
* _\[ASSUMPTION] Victim opens the file_&#x20;
* There's a hardcoded string (\~2.8 MB) that's converted from base64 to an Array Buffer
* This array buffer (which is an ISO file) is written onto disk using Inbuilt API calls&#x20;
* This ISO file contains 3 files: an exe and 2 DLLs. While these were interesting, it's a story for another day.

## Analysis In-Detail:

At the first look, the HTML dropper looks to be built in a not-so-sophisticated way as we encounter a malicious domain where the malware is communicating. What's more eye-popping for a malware analyst than a malicious domain hardcoded in a malware :joy: &#x20;

<figure><img src="../../.gitbook/assets/image (36).png" alt=""><figcaption><p>Nobelium's HTML loader</p></figcaption></figure>

Analyzing the code deeply, the first function is taking an input text and using the "_window.navigator.msSaveOrOpenBlob_" API call to download a file. Now, I'm not a JS expert by any means but I can do good googl-ing (if that's even a word, lol) and looks like our folks have taken some inspiration (pun intended) from [CodePen](https://codepen.io/kallil-belmonte/full/oNwZKwV). After all, they are like normal developers who love copying code from online :joy:

<figure><img src="../../.gitbook/assets/image (54).png" alt=""><figcaption><p>Code on Code Pen</p></figcaption></figure>

Moving On, they seem to be sending a beacon-ping (kind off like a Hi, someone clicked me) to their malicious URL along with the IP of the user and the user agent. I'm not sure why they were sending a request to IPIFY. I assume they wanted to get the current IP of the user but they're not really utilizing it. Seems like unfinished code (not surprised). However, this seems to be just a function and we'll have to see when this is actually called.&#x20;

Further down, there seems to be a string (\~2.8 MB) which is base64 encoded.&#x20;

<figure><img src="../../.gitbook/assets/image (50).png" alt=""><figcaption><p>Malware Sample Analysis</p></figcaption></figure>

Below that is the function which is kind off the one which does all the magic; Again, not a JS expert but looks like they copied yet another code and this time from [StackOverflow](https://stackoverflow.com/a/21797381).&#x20;

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption><p>Malware Sample </p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (59).png" alt=""><figcaption><p>Code on Stack Overflow </p></figcaption></figure>

Combining both the pieces together, it looks like the JS is trying to put the base64 string into an array buffer and write to the disk using the previously discovered function. Dynamic analysis indicates that it's an ISO file containing possibly malicious samples.

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption><p>The malicious ISO file </p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (51).png" alt=""><figcaption><p>Contents of the malicious ISO </p></figcaption></figure>

There seems to 2 DLLs and 1 Exe that were dropped as a part of the malware package. Looks interesting and will definitely keep me occupied after work :ninja:

This looks like a previously documented variant&#x20;

* [https://www.microsoft.com/en-us/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/ ](https://www.microsoft.com/en-us/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/)
* [https://www.cyfirma.com/outofband/html-smuggling-a-stealthier-approach-to-deliver-malware/](https://www.cyfirma.com/outofband/html-smuggling-a-stealthier-approach-to-deliver-malware/)

References:&#x20;

* [https://digital.nhs.uk/cyber-alerts/2021/cc-3878](https://digital.nhs.uk/cyber-alerts/2021/cc-3878)
* [https://www.fortinet.com/blog/threat-research/nobelium-returns-to-the-political-world-stage](https://www.fortinet.com/blog/threat-research/nobelium-returns-to-the-political-world-stage)&#x20;
* [https://blog.sekoia.io/nobeliums-envyscout-infection-chain-goes-in-the-registry-targeting-embassies/](https://blog.sekoia.io/nobeliums-envyscout-infection-chain-goes-in-the-registry-targeting-embassies/)
