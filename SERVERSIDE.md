# 1.Authorization and Session vulnerabilities
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
### Description:-
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


# 3. Password reset flow
## Description:- 
A password reset endpoint allowed the attacker to initiate and complete resets without proper verification of identity or ownership
## Steps to reproduce:-
1 Login as a admin on Browser A & keep it.

2 Open Browser B (or incognito/private). Go to Password Recovery page by clicking Forgot your password? from the login page.
Note the sessionID cookie. Enter the email address and Proceed >.

3 Open the reset link received by email on Browser B. Note that the sessionID remained the same. Change the password. Note that the user have logged to dashboard without invalidating the current session and the sessionID remained the same.

4 Come back to Browser A and note that the user session is still valid.

### Attack vector

* Invalidating other existing session: The sessionID cookie which drives everything about user accounts, is set to expire on Session which means until the user explicitly clicks the Logout or the browser/tab is closed. Thus if an attacker some how (phishing or brute force) compromised an user account, the hacked session remained the same even though the account owner resets the password or change the email address.
* Invalidating the current session after the password recovery: Attacker with physical access to the user's computer, leaves the Revive Adserver login page open by noting down the sessionID. User comes, resets the password and logged in. As the attacker knows the sessionID, he can use that in logging in as the user. This works even the attacker not having admin access on the system to install a keylogger and valid until the user logs out and the session is destroyed.

### Impact
* The weakness allowed unauthorized password resets → account takeover.
* Once the attacker reset the password, they could log in as the victim.
* This kind of flaw undermines trust in the authentication system and jeopardises user accounts.

### Mitigation
Use Cryptographically Strong Reset Tokens

Token must be generated using a CSPRNG (e.g., 32+ bytes, URL-safe).

Never use Base64 of user ID, timestamps, sequential numbers, or hashed emails.

Example used by Google: 256-bit random token mapped to server-side table.

# 4. 2FA Byepass Technique
### Description:-
this is a failure in null check of the entered code. In simple terms, the 2FA while logging in can be bypassed by sending a blank code. This could be because of incorrect comparison of entered code with true code. A pre-validation (may be null check) before comparing the codes would fix the issue
Affected URL or select Asset from In-Scope: Glassdoor 2FA
Affected Parameter: code
### Vulnerability Type:
Improper Authentication
### Steps To Reproduce:
1 Login to Glassdoor and navigate to https://www.glassdoor.com/member/account/securitySettings_input.htm

2 Enable 2FA

3 Logout

4 Login again and notice OTP is asked

5 Now using Burp suite intercept the POST request by sending incorrect code. [Do not forward]
Before forwarding the request to server, remove the code and forward
Turnoff Intercept and notice that your login request has been fulfilled

### Impact
2FA Protection bypass. Attacker could gain access despite the 2FA protection by victim


# 5. Session Fixation
### Found in:-
Nextcloud Talk
### Description:-
The password-protected room in Nextcloud Talk does not regenerate or invalidate the guest session ID after a user enters the room password.
### Steps to reproduce:-
1 userA shares a talk room and protects it with a password

2 userB opens links but doesn't enter the password yet

3 Attacker steals the cookies from userB

4 userB logs in

5 attacker is now also able to read the conversation etc

### Impact
In short the attacker is able to take over the session of the guest userB on this talk room.
### Mitigation
The session id should be renewed once the password is entered.

# 6.JWT misconfiguration
### Found on:-
jira
### Description:
As we mentioned earlier, the HackerOne for Jira application, after installing it, creates an integration between the HackerOne platform and the atlassian where cases can be synchronized from HackerOne to atlassian
And vice versa. So, after installation, administrators jira account is allowed to go https://YOUDOMIN.atlassian.net/plugins/servlet/ac/com.hackerone/get-started-with-hackerone-on-jira When going to this page, the following message will appear:
Image
•
37.89 KiB
•
F1196098: H1PlugConf.png




When you click on "click here", you will be directed to a link this "https://hackerone.com/apps/atlassian/claim-app?jwt=<TOKEN>" containing JWT parameter to complete the integration process. So. Based on the About jira description, an employee with "BSSIC" privileges is not allowed to access the application configuration. After testing if the HackerOne for Jira app. checks the permissions of Jira users before providing the user with the JWT, it is found that the [HackerOne for Jira] application does not verify the user's permissions and generates the JWT code for a user with basic privileges. This allows this malicious user to link their hackerone account to an instance of a jira that they do not own. Which leads, for example, to leak names of private projects or create issues in private projects .. etc
### Steps To Reproduce

Go to Jira cloud and create jira instance.

Add user with Basic roles.

The administrator creates 8 projects and is restricted to accessing 5 projects for the administrator only.

Admin Install HackerOne for Jira app.

User Go to {BaseUrl}/plugins/servlet/ac/com.hackerone/get-started-with-hackerone-on-jira

User steals a hackerone generated configuration link https://hackerone.com/apps/atlassian/claim-app?jwt=<TOKEN> and uses it to link a Jira instance to their hackerone account

Now user can create issue in private project or linked H1 report with private issue project.

### Impact
attacker can Create issue in priavet jira Project
attacker can Leaked priavet jira Project name.
When an administrator tries to link an instance of jira to the H1 account, they will not be able to because the instance has been linked to the attacking H1 account


# 2.Authorization / Access Control Issues
Authorization or access control issues occur when an application fails to properly enforce what actions a user is allowed to perform after authentication. Even if users are logged in correctly, the system must still verify whether they have the correct permissions (role, privilege, or ownership) to access a resource or perform an operation.

# Variants:-
# 1.IDOR
### Description
Insecure Direct Object Reference (called IDOR from here) occurs when a application exposes a reference to an internal implementation object. Using this way, it reveals the real identifier and format/pattern used of the element in the storage backend side. The most common example of it (altrough is not limited to this one) is a record identifier in a storage system (database, filesystem and so on).
IDOR do not bring a direct security issue because, by itself, it reveals only the format/pattern used for the object identifier. IDOR bring, depending on the format/pattern in place, a capacity for the attacker to mount a enumeration attack in order to try to probe access to the associated objects.
### found on :
https://hackerone.com/graphql
### Steps to reproduce:
Create two h1 accounts as attacker and victim and then create a scope asset respectively

Victim create a new custom tag

Assign tag to attacker's scope then capture the request

You will obtain a request whose the operationName: AddTagToAssets and contains tagId parameter which has a base64 cipher text within

If you decode it, the result's format is gid://hackerone/AsmTag/4979xxxx

Bruteforce the AsmTagId then replace to your tagId parameter

You will obtain 200 OK response status contains the error messages:

Code
{"data":null,"errors":[{"message":"AsmTag does not exist","locations":[{"line":2,"column":3}],"path":["addTagToAssets"],"type":"NOT_FOUND"}]}

But no worries, this issue can still be produced if you look at your assets page

Successfully to disclose victim's custom tag without any interaction with victim

Detail about vulnerability and PoC on the attachment video file below.

### Remediation:
IDOR means that you directly alter a database object by using user submitted data in the query before checking or validating that data.
You should first check if the user that submits the request isn't tampering and isn't submitting any ID's that do not belong to his account.
### Impact
Lead to disclose all of victim's new custom tags without any interaction with victim.

# 2.BOLA
### Description
When an invalid email address/password is entered, the Web Application will not authenticate the user. But nevertheless, it is conceivable for an attacker to get around authentication and log in as anyone else, leading to Complete Account Takeover.
### Steps To Reproduce:
Create Two Test Account (Attacker & Victim)

Using attacker's account, login at ███████

Capture request with Burp.

Without sending request to "Burp Repeater", modify attacker's email to victim's email. For example REDACTED+██████ to REDACTED+█████.

Change the param value:false, to value:true, and click send.

Notice, attacker has successfully bypassed the authentication to login as the victim without any interaction.

### Supporting Material/References:
### Request
Code
POST /app/login HTTP/1.1
Host: mtnmobad.mtnbusiness.com.ng
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.27 Safari/537.36
....snip....
Connection: close
{
	"params":{
		"updates":[
		{
			"param":"user",
			"value":{
				"userEmail":"REDACTED+██████",
				"userPassword":"#######"
				},
				"op":"a"
				},
				{
					"param":"gateway",
					"value":true,
					"op":"a"
					}
					]
### Response
Code
HTTP/1.1 200 OK
Server: nginx
....snip....
{
	"error":false,
	"response":{
		"id":"/703",
	"name":"Victim ******",
	"type":"Account",
	"level":0,
	"notes":{
		},

### Impact
Supposing there are 100,000 users available, a malicious actor will enumerate all 100,000 emails for all users to achieve a mass account takeover. Additionally, an attacker can lockdown an account, delete an account, change account info, and perform large data leaks.

# 3.Horizontal Privilege Escalation
### Description-
access controls are broken, unauthorized users may gain access to sensitive information, modify data, or perform actions that they shouldn't be allowed to. This can lead to various security risks, including data breaches, unauthorized privilege escalation, and other malicious activities.
### Steps to Reproduce:-
STEP 1:-
Go to https://mtn.ng/offers/
nter your number and click on Submit Button
Click on Ok

STEP 2:
Enter the OTP code sent to your number
click on Validate

STEP 3:
MTN offer dashboard will automatically display
https://mtn.ng/offers/list?phone=2348160817474

STEP 4:
I changed the number that i logged in with my alternative number and it works successfully
https://mtn.ng/offers/list?phone=2349138557692
In this situation an attacker change the phone number to number of his choice
Example:
If you click on this link you will have access to my MTN number without an authentication
https://mtn.ng/offers/list?phone=2349138557692

### Impact
This vulnerability allow an attacker to access any MTN number in Nigeria and allow threat actors to subscribe data or airtime to the victims.
It can also allow attackers to send messages of their choice to their targeted victims and the victims might think that the message come from MTN.

# 4.Vertical Privilige Escalation
### Found On
The issue was identified in the Lovable AI Workspace Management API, specifically the endpoint:
POST /workspaces/<WORKSPACE_ID>/tool-preferences/ai_gateway/enable
### Description
The API endpoint responsible for enabling or disabling the workspace-wide Lovable AI feature fails to enforce proper server-side role authorization.
Although the ability to toggle this feature is intended exclusively for workspace Owners/Admins, an account with the Editor role can directly call the same endpoint using its own JWT and successfully disable the feature.
### Steps to reproduce:-
1. Log in as Admin (Account A)

Navigate to workspace settings and disable the Lovable AI feature.

Capture the network request responsible for this action:

Captured Admin Request

POST /workspaces/<WORKSPACE_ID>/tool-preferences/ai_gateway/enable HTTP/2
Host: lovable-api.com
Authorization: Bearer <OWNER_TOKEN>
Content-Type: application/json

{"approval_preference":"disable"}

2. Modify the Request

Replace the Authorization header with the Editor’s JWT token:

Modified Request Using Editor Token

POST /workspaces/<WORKSPACE_ID>/tool-preferences/ai_gateway/enable HTTP/2
Host: lovable-api.com
Authorization: Bearer <EDITOR_JWT>
Content-Type: application/json

{"approval_preference":"disable"}

3. Send the Request as Editor

Even though Editors should not be allowed to toggle this setting,
the server accepts the request and disables Lovable AI across the workspace.

### Impact
The Lovable AI feature powers all the AI-assisted components of a workspace, including:
* Prompt integrations
* AI-generated content
* Model-driven actions
* Automated assistance and tooling
* Any feature using the AI Gateway backend
Since only Admins are supposed to control this workspace-wide setting, allowing an Editor to disable it creates a significant disruption:
* Editors can break functionality for all workspace members.
* Critical AI features become non-functional.
* Core workflows relying on AI are halted.
* This leads to workspace-wide operational downtime.
* Represents a clear violation of role-based access control (RBAC) expectations.
* This vulnerability constitutes Broken Access Control and allows unauthorized privilege escalation from Editor → Admin-level action.

# 6. HTTP method tampering byepass
### Found On
The issue was discovered on DRIVE.NET
### Description
The target server improperly reveals the full list of supported HTTP methods when sent an invalid or unsupported method. Instead of securely rejecting the request, the server responds with a "405 Method Not Allowed" status and an Allow header listing all permitted methods.
### Steps to Reproduce
1. Navigate to the target URL
Open the vulnerable endpoint in a browser or through Burp Suite.

2. Intercept the Request
Use Burp Suite to intercept the outgoing GET request.

Example original request:

GET /<path> HTTP/1.1

Host: <target>

3. Modify the HTTP Method
Replace the method GET with an invalid method such as:

ABCD /<path> HTTP/1.1

Host: <target>

4. Forward the Request
Forward the modified request to the server.

5. Observe the Response
The server returns:

405 Method Not Allowed or 501 Method Unimplemented, and

An Allow header listing enabled methods.

Example response headers:

HTTP/1.1 405 Method Not Allowed

Allow: GET, POST, PUT, DELETE, OPTIONS

The presence of PUT and DELETE confirms insecure method configuration.

### Impact

The server discloses sensitive HTTP methods (e.g., PUT, DELETE) to any client.

If these methods are enabled without access controls, an attacker may:
* Upload arbitrary files via PUT (potential web shell or malicious content).
* Modify or overwrite existing server files.
* Delete resources using DELETE.
* Bypass application-layer restrictions by interacting directly with the server.


# 3. Business Logic Vulnerabilities
Business logic vulnerabilities arise when an application’s intended workflow, rules, or processes can be manipulated in ways the developers did not anticipate. Instead of exploiting technical bugs like XSS or SQL injection, attackers exploit flaws in how the system is designed to operate.


# Variants:-
# 1.Rate limit bypass
### Found On
The issue was identified on the login portal of Acronis Passport:
https://passport.acronis.work/
### Description
The login system relies on the client’s IP address to enforce rate limits, geolocation restrictions, and OTP throttling. However, the server trusts the user-supplied X-Forwarded-For header without validation. By injecting this header, an attacker can spoof arbitrary IP addresses and evade all location- or IP-based access control mechanisms.

This results in:

Bypassing rate-limit protection (429 Too Many Requests)

Bypassing location-based login restrictions (e.g., country-based IP checks)

Bypassing OTP submission rate limits

Making login attempts using employee emails from unauthorized locations

Spoofing internal or employee IP ranges, allowing login attempts as if originating from trusted networks

### Steps to Reproduce
1. Bypass Rate Limit

Attempt 10 failed logins → server returns 429 Too Many Requests.

Repeat the same request but add:

X-Forwarded-For: 12.34.56.78

The request is accepted, and the rate limit resets because the server trusts the spoofed IP.

Using Burp Suite Intruder, keep rotating IPs + emails → rate limits remain bypassed even after hundreds of attempts.


2. Bypass Country-Based Login Restriction

Choose a targeted employee email (e.g., publicly found email such as ab@acronis.com
).

Normally, the login attempt fails with an error (e.g., ERR-B258C8) because the attacker is not from the allowed country (e.g., Bulgaria).

In Burp Suite → Proxy → Match & Replace:

Replace nothing with:

X-Forwarded-For: 109.104.192.0


(IP address belonging to Bulgaria)

Go to https://passport.acronis.work/login again.

Attempt login with the victim’s email — the restriction disappears.

Same spoofing bypass works on the OTP submit endpoint.

### Impact

This vulnerability allows attackers to:

Bypass IP-based rate limits on login and OTP endpoints.

Bypass country/IP restrictions, enabling login attempts as if coming from trusted regions.

Submit unlimited login and OTP attempts, enabling practical brute-force or OTP abuse.

Spoof employee or internal IP addresses, causing the system to treat attacker requests as trusted.

Brute-force credentials or OTP codes without restrictions, leading to potential account takeover of employee accounts.


# 3. Workflow byepass
### Found On
The issue was identified in Shopify Flow’s connector workflow system (flow-connectors.shopifycloud.com)
### Description
Shopify Flow generates signed URLs for connector actions (Google Sheets, Trello, Asana) that remain valid for one hour, controlled by timestamp and path_hmac.
However, even after a staff member is removed from a store, any previously generated signed URLs remain reusable as long as the attacker refreshes the timestamp before it expires.
The system does not invalidate prior signed URLs when:

a staff member is removed,

a new connector is added,

a new timestamp or path_hmac is generated by the store owner, or

a new account is connected to the workflow app.
### Steps to reproduce:-
1. Prepare a Limited Staff Account

Owner logs into the shop.

Adds a staff member with only “Apps” permission.


2. Install Shopify Flow

Install Flow from: https://apps.shopify.com/flow

Login using the staff account.

Navigate to:
https://<shop>.myshopify.com/admin/apps/flow/connectors

3. Link External Services

Staff member connects:

Google Sheets

Trello

Asana

This generates a signed URL like:

https://flow-connectors.shopifycloud.com/gsheet/connect?
shop_domain=<shop>&shop_id=<id>&timestamp=<TS>&path_hmac=<HMAC>

4. Remove the Staff Member

Owner removes the staff account completely.


5. Use Saved Signed URL After Removal

Using the previously saved URL (as a removed staff member):

it continues to work for 60 minutes

access to connector settings is still granted.


6. Refresh the Signed URL Before Expiration

Before the 60-minute window expires:

open the saved URL

click Disconnect

then click Connect

connect any Google/Trello/Asana account

A new timestamp and path_hmac are generated and returned to the attacker.


7. Repeat Token Refresh Indefinitely

By repeating steps 6 and 7 every ~45 minutes, the attacker can maintain permanent access, even though:

the staff account is deleted,

owner reconnects services,

new HMACs are generated.

Old and new signed URLs remain valid simultaneously, which is the core vulnerability.

### Impact
This bypasses Shopify’s access control model entirely and allows privilege persistence after user deletion—an extremely severe workflow bypass / business logic failure.

# 3.Price manipulation
# found on:-
zomato
### Description:-
found an issue in support rider amount calculation at the time of checkout where the amount is tamperable by negative fraction of rupees which makes the total amount decreased by maximum of 1rs.
### Steps to reproduce:-
1-Goto - zomato.com

2 - Add anything to your cart

3- At the checkout page , Add some money to Support Riders , click on any 25,50,100

4- Intercept the request of adding support rider money.

5- Change the price of Support Rider to " -0.99" in both fields of donation money.

6- Forward the request , the Cart value will change.

7- Pay by any platform, order will get placed.

### Impact:-
Price Manipulation in Support Rider
