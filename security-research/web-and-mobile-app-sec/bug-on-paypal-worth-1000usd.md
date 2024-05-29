# Bug on paypal worth 1000$

\*\*\*\*\*\*\*\*

This is an older post (written around \~2015) and ported from my old blog. Please excuse if there are any mistakes or inaccuracies. If you find any issues, please head over to the home page > contact me. Thanks.

\*\*\*\*\*\*\*\*

Hello Folks, Hope your having a wonderful time.. I’m here today to blog about an issue i found and reported in Paypal’s Website as a part of their Bug bounty program. The Vulnerability was Captcha Bypass on the domain “ [www.paypal.com](https://t.umblr.com/redirect?z=http%3A%2F%2Fwww.paypal.com\&t=ZDNlOGI4ZjRlYThkOWY1MWNmNzJiNTRjMWJjZjY0OWE3NTVlYzk1YyxhU2w1MTZDNw%3D%3D\&b=t%3AflGJNnVLZW3FCxMTSU1yAw\&p=https%3A%2F%2Fpbssubhash.tumblr.com%2Fpost%2F108330569994%2Fpaypal-captcha-bypass\&m=1\&ts=1704079624)”

Description :- The bug was very simple, There was a feature called “resend-email” after we request an email to reset the password and unfortunately(for paypal) and fortunately(for me) the resend email feature lacked the rate limiting protection and abusing the same i was able to bypass the captcha. Actually it was not a complete bypass of captcha, it was indirect bypass by abusing a feature of paypal.

Here is a video demonstrating the Proof Of Concept. [https://vimeo.com/86767236](https://t.umblr.com/redirect?z=https%3A%2F%2Fvimeo.com%2F86767236\&t=NjAyOGY2ZDJjNjAxNGFiMmUxOGYyYjA1ZDBlMjU2NDdlZmMxZjNkZCxhU2w1MTZDNw%3D%3D\&b=t%3AflGJNnVLZW3FCxMTSU1yAw\&p=https%3A%2F%2Fpbssubhash.tumblr.com%2Fpost%2F108330569994%2Fpaypal-captcha-bypass\&m=1\&ts=1704079624) Password for the video is :- letmein\_1234

{% embed url="https://vimeo.com/86767236" %}

Hope you’ve enjoyed my writeup.

It’s a pretty short one but since it’s my first i guess i’ve some time to improve my blogging skills ;)

I look forward to share some more of my findings here. Just stay tuned :)

This was one of the bug i’ve reported to paypal and there are several other’s which i’ll be sharing i the mere future :)

Reward :- 1000$, Hall of Fame entry ! :)

Bye ! :)
