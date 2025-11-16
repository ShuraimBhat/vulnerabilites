# Authorization and Session vulnerabilities
These vulnerabilities arise when a system fails to properly verify user identity or securely maintain a user’s session. Weak or improperly enforced authentication allows attackers to impersonate users, while poor session management lets attackers hijack active sessions. Common problems include weak passwords, lack of multi-factor authentication, insecure session IDs, session IDs exposed in URLs, predictable tokens, missing session timeout, and failure to regenerate session IDs after login. When exploited, these flaws can lead to unauthorized access, privilege escalation, data theft, and complete account takeover.

# Variants:-
#  1. Broken Authentication and Session Management
### Found in:- 
http://en.instagram-brand.com/register/reset/<the security token here>?email=<email address here
### Description:- 
The password reset links issues by Instagram Brand gets delivered to users inbox with a http scheme and NOT https scheme.
### Steps to reproduce:-
* 1 Request for password reset using https://en.instagram-brand.com/register/signin
* 2 Go to your inbox
* 3 Right click on that hyperlink and copy and paste it in notepad. (HTTP scheme is seen here)
* 4 Now Attach a local proxy tool to your browser.
* 5 Request the copied link in that browser and keep on intercepting.
* 6 The first request goes in HTTP like this:
* GET /track/click/30956340/instagram-brand.com?p=<token here> HTTP/1.1 Host: mandrillapp.com User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 Accept-Language: en-US,en;q=0.5 Accept-Encoding: gzip, deflate Connection: keep-alive Upgrade-Insecure-Requests: 1
* 7.The response to that request is:
HTTP/1.1 302 Moved Temporarily Server: nginx/1.6.3 Date: Thu, 16 Feb 2017 02:58:53 GMT Content-Type: text/html; charset=utf-8 Set-Cookie: PHPSESSID=dc43ed4a78f737e1cff9ecf05ede3680; expires=Thu, 16-Feb-2017 12:58:01 GMT; path=/; secure; HttpOnly Expires: Thu, 19 Nov 1981 08:52:00 GMT Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0 Pragma: no-cache Set-Cookie: PHPSESSID=dc43ed4a78f737e1cff9ecf05ede3680; expires=Thu, 16-Feb-2017 12:58:01 GMT; path=/; secure; httponly Location: https://instagram-brand.com/register/reset/<new token>?email=<your email> Vary: Accept-Encoding Content-Length: 0
* 8.Then the next request is:
GET /register/reset/<token>?email=<email> HTTP/1.1 Host: instagram-brand.com User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 Accept-Language: en-US,en;q=0.5 Accept-Encoding: gzip, deflate, br Cookie: pll_language=en; _ga=GA1.2.1670792457.1487004320; _gat=1 Connection: keep-alive Upgrade-Insecure-Requests: 1
* 9.The response is:
HTTP/1.1 302 Found Server: nginx Date: Thu, 16 Feb 2017 03:00:30 GMT Content-Type: text/html; charset=utf-8 Content-Length: 0 Connection: keep-alive Location: https://en.instagram-brand.com/register/reset/<token>?email=<email> X-rq: lhr2 102 131 3129 Age: 0 X-Cache: miss
* 10.The final request is:
GET /register/reset/<token>?email=<email> HTTP/1.1 Host: en.instagram-brand.com User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:51.0) Gecko/20100101 Firefox/51.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 Accept-Language: en-US,en;q=0.5 Accept-Encoding: gzip, deflate, br Cookie: pll_language=en; _ga=GA1.2.1670792457.1487004320; _gat=1 Connection: keep-alive Upgrade-Insecure-Requests: 1
* 11.The final response is:
HTTP/1.1 404 Not Found Server: nginx Date: Thu, 16 Feb 2017 03:01:58 GMT Content-Type: text/html; charset=UTF-8 Connection: keep-alive X-Frame-Options: deny X-hacker: If you're reading this, you should visit automattic.com/jobs and apply to join the fun, mention this header. Link: <https://instagram-brand.com/wp-json/>; rel="https://api.w.org/" X-rq: lhr1 102 131 3129 Age: 0 X-Cache: miss Vary: Accept-Encoding Content-Length: 28183

### Impact:-
This causes an attacker stealing those links and performing mass account takeovers and security compromises.

### Mitigation:-
This issues has a very easy solution. I have myself performed this and it worked !!.
Whenever the code responsible for sending password reset link makes those links, just add https as scheme instead of http. And you will observe that now all the accounts are safe and data cannot be stolen.

# 2. Credential stuffing
### Found in:-
23andMe user accounts
### DEscription:-
The attacker used previously compromised credentials from unrelated breaches and attempted automated logins on 23andMe’s authentication endpoint.
Because a portion of users reused passwords on multiple services and the platform lacked strong protection (mandatory MFA, effective rate-limiting, anomaly detection), the attacker successfully authenticated into a number of user accounts.
### Steps to Reproduce:-
1 Prepare Credential List
Gather a list of known breached credentials (email + password pairs) belonging to test accounts.

2 Configure Automated Login Tool
Use any credential-stuffing automation (Burp Intruder, Hydra, Python script).
Set the target to the application’s /login endpoint.

3 Execute High-Volume Login Attempts
Send the credential list to the authentication endpoint at a controlled but high rate.
Observe the following:
* No effective rate-limiting
* No CAPTCHA
* No MFA prompt
* No account lockout after failures

4 Identify Successful Logins
If reused credentials are accepted, the platform logs in the attacker normally without any alert.

5 Access Connected Features (Privilege Abuse)
For any account successfully accessed:
* Open DNA Relatives
* Open Family Tree
Confirm that extended information is viewable without additional authorization.

6 Review Server Response & Logging
Check if:
* The system generates alerts for anomalous login behavior
* Session tokens regenerate after login
* Any IP throttling restricts the activity

### Impact:- 
* Unauthorized login to legitimate user accounts.
* Exposure of profile details such as name, location, birth year, shared DNA %, and relation data.
* Data exposure extended from ~14,000 directly compromised accounts to millions of related profiles.
* Increased risk of identity fraud, targeted phishing, and genetic-relationship inference.
* Regulatory penalties and reputational damage to the organization.

### Mitigation:-
* Enforce mandatory MFA for all accounts.
* Implement aggressive rate-limiting on login endpoints.
* Introduce CAPTCHA after multiple failures.
* Use device fingerprinting and anomaly-based login detection.
* Enforce password reuse detection and breach password alerts.
* Add real-time automated bot detection.





