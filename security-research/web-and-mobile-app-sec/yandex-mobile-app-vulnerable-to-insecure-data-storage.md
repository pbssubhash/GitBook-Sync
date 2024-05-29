# Yandex Mobile App vulnerable to Insecure Data storage

\*\*\*\*\*\*\*\*

This is an older post (written around \~2015) and ported from my old blog. Please excuse if there are any mistakes or inaccuracies. If you find any issues, please head over to the home page > contact me. Thanks.

\*\*\*\*\*\*\*\*

### Vulnearbility on Yandex.Mail Mobile application - Allows to hack into newly created accounts created using the app

Hey Fellas,\
Hope your doing great! It’s been a while i’ve been active online.. I’m being through a hectic schedule of exams. Still would like to take time sharing one of my find on Yandex.Mail Application. The Yandex Mail Application can be found [here.](https://t.umblr.com/redirect?z=https%3A%2F%2Fplay.google.com%2Fstore%2Fapps%2Fdetails%3Fid%3Dru.yandex.mail\&t=NmI0ZjA1M2MxNTc4YTlhMjViNTNmNTQ3YWZhZjQzMmQxYzEzYTdjMixEY2x6aXVVYQ%3D%3D\&b=t%3AflGJNnVLZW3FCxMTSU1yAw\&p=https%3A%2F%2Fpbssubhash.tumblr.com%2Fpost%2F109971591144%2Fvulnearbility-on-yandex-mail-mobile-application\&m=1\&ts=1704079610)\
Fine, Let me get into the description of the vulnerability. The vulnerability goes with the name of “Insecure Data Storage”. You can find more information just by googling the name yet i’ve added some references at the end of the post ;)\
The vulnerability exists because the data which the developer is storing locally is not being stored in a secure manner.\


{% embed url="https://www.youtube.com/watch?v=dTGFslSW2mI" %}

\
How to exploit this issue?\
Well, The question comes to everyone’s mind that how to exploit.. The attack scenario goes like this :- The attacker creates a malicious application which steals the text that is present in the local storage. So, The victim creates his account but doesn’t realise that his phone has the virus and as soon as the victim creates, the attacker steals and uploads it to a remote server and reads it there. See [this](http://resources.infosecinstitute.com/android-hacking-security-part-10-insecure-local-storage/) for more information on how to exploit this issue.This is an excellent article and a good guide which i suggest for newbies in the Mobile Applcation security field.

\
How to patch this type of issues?\
Well, The answer is just don’t store the credentials in clear text in the local storage.\


\
Reference:-\
[https://www.owasp.org/index.php/Mobile\_Top\_10\_2014-M2](https://www.owasp.org/index.php/Mobile\_Top\_10\_2014-M2)
