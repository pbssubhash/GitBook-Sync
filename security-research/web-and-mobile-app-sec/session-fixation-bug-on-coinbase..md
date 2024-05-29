# Session fixation bug on coinbase.



\*\*\*\*\*\*\*\*

This is an older post (written around \~2015) and ported from my old blog. Please excuse if there are any mistakes or inaccuracies. If you find any issues, please head over to the home page > contact me. Thanks.

\*\*\*\*\*\*\*\*

Hey, Today I am going to share one of my finding on coinbase , a leading BTC trading platform.

The bug was session fixation bug.

Briefly,

When a new cookie was issued , the old cookie was still being authenticated and the user is not logged out.

Attack Scenario :&#x20;

Session Fixation is an attack that permits an attacker to hijack a valid user session. The attack explores a limitation in the way the web application manages the session ID, more specifically the vulnerable web application. When authenticating a user, it doesn’t assign a new session ID, making it possible to use an existent session ID. The attack consists of inducing a user to authenticate himself with a known session ID, and then hijacking the user-validated session by the knowledge of the used session ID. - OWASP

Poc of Hackerone :-&#x20;

When a request with an invalid authenticity\_token is received, the user is logged out (tested for updating user’s Phone Number) and the user receives a new session cookie, which is not authenticated at this point. However, the authenticated session cookie used by a user before logging out is still active.\
This is the same Bug as : [https://hackerone.com/reports/737](https://hackerone.com/reports/737)

Actually, \
Here a New Authenticated Session Cookie is being served but the old cookie is still being authenticated by the server which is infact a bad practice ..\
Session handling is a known security concern for Web applications. These kindoff poor session management practices can lead to account takeover using Session Hijacking.!\
Improper session management can sometimes lead to an attacker hijacking an active session and assuming the identity of a user.\
Here in this context, I can say that the cookie which is to be expired is still being validated by the server.

Bug URL :- https://hackerone.com/reports/6660

Note : You may not view the bug as they have not approved my request to disclose it there , feel free to check it frequently as it may take some time for them to approve ;)&#x20;

Have a nice day,

Please drop your comments :)&#x20;
