---
layout: post
title: Active directory
date: '2024-01-15'
categories: [HTB]
tags: [CVE]
---

```shell
pl4int3xt@archlinux ~> ffuf -w ~/Downloads/wordlists/seclists/directory-list-2.3-small.txt:FUZZ -u https://bizness.htb/control/FUZZ -fw 10468

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : https://bizness.htb/control/FUZZ
 :: Wordlist         : FUZZ: /home/pl4int3xt/Downloads/wordlists/seclists/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 10468
________________________________________________

[WARN] Caught keyboard interrupt (Ctrl-C)
```