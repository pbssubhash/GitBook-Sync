# Smishing Traid targets India with large scale "India Post" themed iMessage phish texts

## Background

A lot of people who own an iPhone in India woke up to an "Indian Post" themed phishing iMessage from a spurious and suspicious email ID. A lot of people are talking about it an [analyst blogged](https://hacback17.substack.com/p/phishing-campaign-impersonating-india?r=75yg\&triedRedirect=true) about it to some extent. This blog is an attempt to uncover infrastructure and identify the scale of infrastructure in an attempt to identify the scale of the operation & to discuss the TTPs leveraged in detail.&#x20;

As of 12/07/2024, this campaign was attributed to a group called "Smishing Triad", a Chinese speaking threat actor group that has previously targeted USPS and US citizens in a similar fashion.

**References:**

* [https://www.resecurity.com/blog/article/smishing-triad-targeted-usps-and-us-citizens-for-data-theft](https://www.resecurity.com/blog/article/smishing-triad-targeted-usps-and-us-citizens-for-data-theft) - Excellent analyis doxing the group and their activities.
* [https://malpedia.caad.fkie.fraunhofer.de/actor/smishing\_triad](https://malpedia.caad.fkie.fraunhofer.de/actor/smishing\_triad)

<figure><img src="../../.gitbook/assets/image (76).png" alt=""><figcaption><p>Phishing messages that were received.</p></figcaption></figure>

## The Modus Operandi

The threat actor seemed to be careful not to follow a specific pattern but here's the most general characteristics of these messages:&#x20;

* Sender is \{{something\}}@gmail.com/@outlook.com/@hotmail.com in most cases but in a few cases, custom domains were identified.&#x20;
* The content(hook) is mostly uniform and revolves around a specific package that was undelivered due to incomplete address information and it's urging users to open a link and update the address to receive the post.&#x20;
* The link was seem mostly a typo squat domain of India post. [Click here to learn more about typo squats. ](https://en.wikipedia.org/wiki/Typosquatting)In a few cases, they've used a URL shortener.

<figure><img src="../../.gitbook/assets/image (77).png" alt=""><figcaption><p>The Initial landing page.</p></figcaption></figure>

## Evasion tactics

* The email message contains "Reply with Y" and then come back to active the link. This is to combat Apple's protection of disabling links from unknown senders.

<figure><img src="../../.gitbook/assets/image (78).png" alt=""><figcaption><p>Phishing iMessage links</p></figcaption></figure>

* Few of the landing pages were "User-agent" fenced. For instance, the URL (currently inactive): hxxps(:)//indiapost-id(.)top/BRblTi/ reacts differently for a Windows user agent v/s when used with an iPhone user agent. However this wasn't the case with all the URLs. a few URLs didn't contain this protection.

<figure><img src="../../.gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>

* Usage of Cloudflare was seen in a few URLs. Cloudflare, often used by threat actors to hide the IP behind the domains was also used.
* Few domains that are used in the campaign are not pointed to Department of Posts IP addresses. More details [below](smishing-traid-targets-india-with-large-scale-india-post-themed-imessage-phish-texts.md#attack-timeline).

## Attack Timeline

The attack around first week of April with a domain called "indiaapost\[.]icu" and this domain pointed to 74.48.84.92. As of now, several domains including this one point to "Department of Posts, Government of India". This isn't a legitimate domain but I believe the this is a way to disrupt investigations that are happening right now.

<figure><img src="../../.gitbook/assets/image (81).png" alt=""><figcaption><p>DNS History of a malicious domain</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (82).png" alt=""><figcaption><p>A few domains currently pointing to Dept of posts</p></figcaption></figure>

## **Analysis of Adversary Infrastructure**

The infra is mostly on the following ASNs:&#x20;

* Limenet
* Alibaba Cloud
* Tenacent Cloud
* LightNode&#x20;
* Multacom

The targets currently indentified are: India Post, Singapore Post & Morgan Stanley (IoCs are below)

## **Indicators**

All the indicators are published [here](https://gist.github.com/pbssubhash/d8283527c972b5e7122104887a862e70). **A total of 135 domains and 15 IP addresses are present.**&#x20;

## Recommendation

There is no action required from your end except for not being foolish to click links and submit information. The IoCs are shared with law enforcement authorities.
