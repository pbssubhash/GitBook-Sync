---
description: >-
  This blog post is a first, in a series of articles that share my learning in
  the areas of Attacking and Defending AI.
cover: >-
  https://images.unsplash.com/photo-1524514587686-e2909d726e9b?crop=entropy&cs=srgb&fm=jpg&ixid=M3wxOTcwMjR8MHwxfHNlYXJjaHwzfHxtYWNoaW5lfGVufDB8fHx8MTcwMzc4MDYzOXww&ixlib=rb-4.0.3&q=85
coverY: 0
layout:
  cover:
    visible: true
    size: full
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Attacking using (and defending against) Input manipulation attacks against AI

The techniques discussed here, and the knowledge shared is for collective good of the community and I'm not responsible for any malicious usage of the same. Be responsible and don't be an idiot.

## 🧑‍💻 Background - Why AI Security?

According to me, AI is a broader term for algorithms/technology where machines can perform tasks that generally require human intelligence, such as problem solving, reasoning, etc. AI is currently used in many applications across many sectors. But the most important sector we would be interested in AI's usage in sectors where there is a loss of life or bypass of a security system, etc.&#x20;

Imagine these scenarios:&#x20;

* There is a "_Be on lookout_" guidance on a specific vehicle number. This could be issued post identification of a miscreant using the vehicle. An AI system responsible for identifying this vehicle is bypassed by an adversary.
* Self-driving cars are very popular and are evolving as we speak. Imagine an adversary figures out a way to crash the vehicle or render it useless?&#x20;

AI is being used in medicine, transportation, productivity among many other sectors and ironically these sectors are something that an adversary would love to disrupt or cause harm.

***

## 😎 Approach

We all agree that AI security is important. The intention of the blog is to discuss these attacks from a security engineer's perspective instead of a data scientist and the reason for that is a security engineer will look at the AI system and connected systems (systems which leverage the AI models or provide input to them).&#x20;

***

## 🤔 What's Input Manipulation attack?

According to OWASP's page:

> Input Manipulation Attacks is an umbrella term, which include Adversarial attacks, a type of attack in which an attacker deliberately alters input data to mislead the model.&#x20;

Popularly known as "Adversarial Examples" in the AI world, this is basically a situation where an adversary creates specially crafted input in order to influence the outcome of the AI system. These attacks are created by giving inputs that are intentionally designed to cause an AI model to make a mistake. They are like optical illusions for machines. These inputs can be either in images or audio or textual format.

***

## 💀 Exploitation Techniques

{% hint style="danger" %}
This section covers few easy to exploit and ITW exploitation techniques that I have observed/identified. In no way, I claim this is to be a definitive guide or an exhaustive list.
{% endhint %}

### ⏩ Hide the input from being processed

<table data-card-size="large" data-view="cards"><thead><tr><th></th><th></th></tr></thead><tbody><tr><td>💭 <strong>Description</strong></td><td>It's common sense that if an input is unreadable or unrecognizable, it's not possible for the AI system to function as expected. Hiding input from being processed can be done through plethora of ways. </td></tr><tr><td>🤔<strong>How to prevent?</strong></td><td><ul><li>If an AI system can be fooled by just hiding the input, it means the system isn't built to sanitize the input properly. When the system detects a malformed input such as unable to detect input, it should handle the situation gracefully either by asking for a better input or reducing confidence, etc. The system that's consuming the AI system should handle this situation by alerting the user about possible misclassification.</li><li>One elegant way to manage such scenario is how proxies classify websites which are unreachable. Often red teamers use captchas to avoid the websites from being scanned. Proxy systems classify the website as "Unclassified", and they're blocked by default (in most cases).</li></ul></td></tr><tr><td>😳 <strong>Exploitation Examples</strong></td><td><ul><li><a href="attacking-using-and-defending-against-input-manipulation-attacks-against-ai.md#bypass-asnr">Bypass ASNR (Autonomous Number Place Recognition Systems)</a></li><li><a href="attacking-using-and-defending-against-input-manipulation-attacks-against-ai.md#bypass-dlp">Bypass of DLP (Data loss prevention) systems</a></li><li><a href="attacking-using-and-defending-against-input-manipulation-attacks-against-ai.md#infiltrate-malware">Bypass of EDRs/AVs to infiltrate malware.</a></li></ul></td></tr><tr><td>🌍 <strong>In the wild exploitation case studies</strong></td><td><ul><li><a href="https://www.glasgowlive.co.uk/news/motorists-issued-warning-licence-plate-25496234">Dirty number plates abused, and police take note.</a></li><li><a href="https://johnjhacking.com/blog/zix-exfiltration/">Red Teamers bypassing DLP using encrypted ZIP</a>.</li></ul></td></tr></tbody></table>

{% tabs %}
{% tab title="Bypass ASNR" %}
**Scenario: Autonomous Number Plate detection system bypass**

Automatic number plate systems are used almost in all developing and developed countries. It is used for detecting vehicles which are stolen, or cars involved in nefarious activities.

By just adding dirt to a number plate, it's possible to bypass the autonomous systems. That being said, not all the ASNR algorithms are vulnerable to do this and it's quite possible to detect dirty number plates but achieving 100% accuracy in this isn't possible if the number can't be read completely. Below is an example of an image of a number plate which is partially filled with dirt bypassing a commercially available number plate recognition system.

<figure><img src="../../.gitbook/assets/image (64).png" alt=""><figcaption><p>Number plate with a lot of dirt on it</p></figcaption></figure>
{% endtab %}

{% tab title="Bypass DLP" %}
**Scenario: Infiltrating Malware using an encrypted zip**

DLP systems are configured to detect sensitive information leaving organization's network. These systems leverage AI models to classify if data is sensitive or not. The system can be as simple as check if data contains social security numbers, etc. (using simple regex) or understand data within a specific context.&#x20;

To bypass these DLPs, data can be encrypted or in a format that is unrecognized or not processed by the system.
{% endtab %}

{% tab title="Infiltrate Malware" %}
**Scenario: Infiltrating Malware using an encrypted zip**

According to a r**Scenario: Infiltrating Malware using an encrypted zipScenario: Infiltrating Malware using an encrypted zip**ecent survey by HP Wolf, 40%+ instances of malware delivered are now archives and are many encrypted ZIPs. Attackers love encrypted zips because it's easy to bypass the old-age systems. The current systems are aware that the file being downloaded is an archive and if it's encrypted, it's possible to detect that. However, it's still not possible to scan contents inside that (except crack open the archive using well known passwords). In this case, there are two ways forward: block encrypted archives completely (or maybe through a whitelist) or let them in completely. Guess what companies are doing now-a-days?&#x20;

Below is an example of an encrypted zip (that's possibly malware) being scanned on Virus total**Scenario: Infiltrating Malware using an encrypted zipScenario: Infiltrating Malware using an encrypted zipScenario: Infiltrating Malware using an encrypted zip**.

<figure><img src="../../.gitbook/assets/image (69).png" alt=""><figcaption><p>Encrypted zip</p></figcaption></figure>
{% endtab %}
{% endtabs %}

All being said, there are several other exploitation techniques that can be classified into this category. Techniques such as Usage of encrypted channels can be counted in this category.

### ⏩ Modify input in another form (language or format, etc.) that's not supported by the algorithm:

<table data-card-size="large" data-view="cards"><thead><tr><th></th><th></th><th data-hidden></th><th data-hidden></th><th data-hidden></th><th data-hidden></th></tr></thead><tbody><tr><td>💭 <strong>Description</strong></td><td>Primarily targeted towards non-image-based algorithms, when the input is sent in a format that's unrecognizable for the system, it'll simply bypass the control.</td><td></td><td></td><td></td><td></td></tr><tr><td>🤔 <strong>How to prevent?</strong></td><td><ul><li>When there's an input that's unrecognized, either AI system or consuming system should handle the situation by either stopping the processing or alert the user.</li><li>Alternatively, the AI model can be trained with possible input types such as for text-based models: emojis can be used for training, etc.</li></ul></td><td></td><td></td><td></td><td></td></tr><tr><td>😳 <strong>Exploitation Examples</strong></td><td><ul><li><a href="attacking-using-and-defending-against-input-manipulation-attacks-against-ai.md#hate-speech-algo-bypass">Hate speech algorithm bypass​.</a></li></ul></td><td></td><td></td><td></td><td></td></tr><tr><td>🌍 <strong>In the wild exploitation case studies</strong></td><td><ul><li><a href="https://newmediaservices.com.au/9-ways-to-bypass-auto-moderation/">Ways to bypass content moderation algorithms</a>.</li><li><a href="https://www.thequint.com/tech-and-auto/tech-news/algospeak-the-simplest-way-to-bypass-algorithms-on-social-media">Quint's case study on bypassing censorship on social media.</a></li></ul></td><td></td><td></td><td></td><td></td></tr></tbody></table>

{% tabs %}
{% tab title="Hate speech algo bypass" %}
**Scenario: Hate speech algorithm bypass**

For example, consider this [notebook](https://colab.research.google.com/github/eugenesiow/practical-ml/blob/master/notebooks/Hate_Speech_Detection_Dynabench.ipynb) which is intended to detect hate speech using RoBERTa model. While variation of algorithms used might be different for enterprise setups (such as social media companies, etc.).

<figure><img src="../../.gitbook/assets/image (67).png" alt=""><figcaption><p>Hate speech detection bypass using emojis.</p></figcaption></figure>

Another example of the same is using a language that is not supported by the algorithm to detect as hate speech. _**Few major social media platforms are vulnerable to these techniques.**_
{% endtab %}
{% endtabs %}

### ⏩ Add noise to the input:

<table data-card-size="large" data-view="cards"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td>💭 <strong>Description</strong></td><td>Noise is basically random gibberish characters added to the input that in most cases will not make a difference to naked eye. When noise is added to the image, the AI model will perceive it differently and misclassify the data.</td><td></td></tr><tr><td>🤔 <strong>How to prevent?</strong></td><td><ul><li>Before the input is used in the AI model, the noise should be removed or at least the fact that noise exists should be considered by the model.</li><li>Alternatively, an AI model can be trained with possible adversarial examples to identify instances of exploitation.</li></ul></td><td></td></tr><tr><td>😳 <strong>Exploitation Examples</strong></td><td><ul><li><a href="attacking-using-and-defending-against-input-manipulation-attacks-against-ai.md#asnr-bypass">ASNR Bypass</a></li><li><a href="attacking-using-and-defending-against-input-manipulation-attacks-against-ai.md#autonomous-driving-car">Autonomous driving car fails</a></li></ul></td><td></td></tr><tr><td>🌍 <strong>In the wild exploitation case studies</strong></td><td><ul><li><a href="https://globalnews.ca/news/3654164/altered-stop-signs-fool-self-driving_cars/">Self-driving cars fails signs.</a></li></ul></td><td></td></tr></tbody></table>

{% tabs %}
{% tab title="Autonomous driving car" %}
**Scenario: Autonomous driving cars**

The noise need not be always invisible to human eye. Consider the stop signs below. They're all legitimate stop signs for a human but they do have noise which \*might\* be incomprehensible for an AI. Of course, the current generation of self-driving cars might be equipped to stop this (which I highly doubt). An attacker could target autonomous vehicles by just pasting stickers or paint the signs and AI system would either interpret a "non-stop" sign as a STOP sign or could ignore an original stop sign.

<figure><img src="../../.gitbook/assets/image (66).png" alt=""><figcaption><p>Funny stop signs that *might* confuse your car's brain.</p></figcaption></figure>
{% endtab %}

{% tab title="ASNR Bypass" %}
**Scenario: Automated Number plate detection system bypass**

Below is an image that I've taken from the internet and added noise using a [tool ](https://pixelied.com)that is available on the Internet. Why is this a big deal? Automatic number plate recognition system is a mission critical system that enabled LEA's monitor the traffic crime landscape. As mentioned earlier, few governments have added protection against the input not being readable at all. However, the following use case might as well just bypass that restriction without being completely uncompliant.&#x20;

<div align="right" data-full-width="false"><figure><img src="../../.gitbook/assets/image (65).png" alt=""><figcaption><p>Comparison between a muddy number plate with noise v/s without noise.</p></figcaption></figure></div>
{% endtab %}
{% endtabs %}

### ⏩ Reverse engineer the algorithm and manipulate.

<table data-card-size="large" data-view="cards"><thead><tr><th></th><th></th><th></th></tr></thead><tbody><tr><td>💭 <strong>Description</strong></td><td>This is more of a broader umbrella technique that covers, what isn't already covered. The idea is to understand the type of parameters that are given importance and modify them. For instance, few spam filtering algos check if an email contains unsubscribe button and they increase trust score if it contains.</td><td></td></tr><tr><td>🤔 <strong>How to prevent?</strong></td><td>If and when adversarial examples are discovered, either the logic has to be patched (if possible) and in the cases where this is not possible, input validation has to be performed and additionally an AI model to detect these malicious inputs can be created and trained with identified examples.</td><td></td></tr><tr><td>😳 <strong>Exploitation Examples</strong></td><td><ul><li><a href="attacking-using-and-defending-against-input-manipulation-attacks-against-ai.md#spam-filtering-bypass">Spam Filtering bypass</a></li></ul></td><td></td></tr><tr><td>🌍 <strong>In the wild exploitation case studies</strong></td><td><ul><li><a href="https://www.trustedsec.com/blog/upgrade-your-workflow-part-2-building-phishing-checklists">Phishing checklist</a></li></ul></td><td></td></tr></tbody></table>

* Identify features that are having most weight associated with them.
* Modify the input by introducing artificial features and provide it as an input.

{% tabs %}
{% tab title="Spam Filtering Bypass" %}
While this is a broad topic, below is an example: [Phishing Checklist | Trusted Sec.](https://www.trustedsec.com/blog/upgrade-your-workflow-part-2-building-phishing-checklists)

The blog covers very good techniques that a red teamer can start with. However, few things caught my attention:&#x20;

<figure><img src="../../.gitbook/assets/image (71).png" alt=""><figcaption><p>Things to take care while phishing.</p></figcaption></figure>

If you are a seasoned red teamer, this wouldn't make a lot of difference to you but certain things like sender reputation or presence of links on the email are few things that are often considered by a spam filtering algorithm to determine if an email is spammy or not. While it's not a new thing, think of it in this way:

* Using trial and error (sending multiple emails) you understood that AI algorithm is basically taking the following parameters into consideration while classifying emails as spammy/not-spammy.
  * Is sender a reputable sender?
  * Does the email have any spammy keywords?
  * Does the email have a valid unsubscribe button?
  * Does the email have any images or links to known trackers, etc.?
* You would incorporate most (if not all) the features to ensure that the email bypasses the spam filters.
{% endtab %}
{% endtabs %}

***

## 😎 How to test if your AI system is vulnerable?

* As with code-based vulnerabilities, having a Whitebox approach helps. As a security researcher, what you are looking for is for "edge cases" where your AI system fails to detect/classify, or mis detects/classifies. More often than not, it's not just the AI system but the system that's consuming the AI is responsible to cover these edge cases.&#x20;
* If you are doing a Whitebox assessment, understanding the logic and identifying the gaps and patching them is the best way. For instance, you know our algorithm doesn't check for some edge case, go and patch it.
* If you are doing a Blackbox assessment, try to fuzz the input with various ways to see if it's giving any unintended or misclassified output. Contrary to traditional fuzzing where in most cases, you know the list of outputs to expect when there is a vulnerability, it's a bit tough to do so in this case as it completely depends on the context.&#x20;

***

## 👈Previous work

Several \*great\* people have worked in this field and have created algorithms that can help create adversarial examples. Below are a few:

* [Fast Gradient Sign Method](https://www.tensorflow.org/tutorials/generative/adversarial_fgsm)
* [Basic Iterative method](https://locuslab.github.io/2019-03-12-provable/)
* [Saliency map method](https://arxiv.org/abs/2009.02738)
* [Projected Gradient Descent ](https://arxiv.org/abs/1808.05537)
* [Carlini and Wagner Attack](https://fairyonice.github.io/Learn-the-Carlini-and-Wagners-adversarial-attack-MNIST.html)
* [AdvGAN](https://github.com/mathcbc/advGAN_pytorch)

***

## 📃 Resources

* The OWASP foundation (famous for OWASP TOP-10), one of the premier most not-for-profit organization that puts up a lot of effort in creating collaterals and guides in various areas of security has recently created an ML Top 10 attacks. [Input manipulation attack ](https://owasp.org/www-project-machine-learning-security-top-10/docs/ML01_2023-Input_Manipulation_Attack.html)is actually rated at the top for this year.&#x20;
* Open AI has created a really [nice blog post](https://openai.com/research/attacking-machine-learning-with-adversarial-examples) related to Adversarial examples (with a good chunk of math).&#x20;

***

If you see any mistake or have any feedback for the post, please reach out to me on [LinkedIn](https://in.linkedin.com/in/pbssubhash) or [Twitter](https://twitter.com/pbssubhash).
