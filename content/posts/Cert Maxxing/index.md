---
layout: post
title: Cert Maxxing
date: '2026-09-16'
description: "Certifications Review"
categories: [certs]
---

This year, I collected three Hack The Box certifications and an amount of character development I absolutely did not budget for.

Consider this my tell-all on the HTB CJCA, CWES, and CPTS exams, with a guest appearance from PNPT because, quite frankly, it earned one.

By the end of this, my dearest gentle reader, you'll have a pretty good idea of what each certification put me through, what I got out of it, and whether any of them deserve a spot on your list.

One disclaimer before we begin: this is my experience, not universal truth. Your background, preparation, strengths, weaknesses, and tolerance for staring at a terminal wondering where exactly your life went wrong may produce a completely different experience.

Now that we've established that...

## REWIND: WHY I EVEN DID THIS?
We need to go back to 2023. I was maybe six months into cybersecurity when, armed with confidence that was. 

I failed TERRIBLY...got zero flags the first time, got 1 on the second try. For a long time, CPTS remained somewhere in the back of my mind. I wanted the rematch, but certification exams cost money, and at the time I hadn't landed a job yet. Fast-forward to 2025 and things looked very different. I became an HTB meetup host and later an ambassador, which came with a few perks, including a Silver Annual subscription. But there was one thing I knew I didn't want to do: repeat 2023. So instead of jumping straight back into CPTS, I decided to be intentional about it. No assuming I knew the basics because I'd been in cybersecurity for a few years. No skipping ahead because something looked familiar. I wanted to build up sequentially.

The plan became:

CJCA → CWES → PNPT → CPTS.

- CJCA would force me back through the fundamentals.
- CWES would strengthen my web and API exploitation skills.
- PNPT would give me more exposure to Windows environments and another approach to penetration testing.
- And then, finally, I'd return to CPTS. 

### So... why was I cert maxxing?
![It's about to go down](thanos-avengers-endgame.gif)
For one, I had the vouchers. There was absolutely no universe in which I was going to watch perfectly good certification vouchers expire even though I almost did.

But there was another, more important reason: I realised I learn better with structure.

I've tried the “I'll just learn whatever interests me” approach several times. It usually ends with me either abandoning a project halfway through or disappearing down a rabbit hole for three weeks because one tiny concept caught my attention, which is not always a bad thing but structured courses give me boundaries.

More importantly, they exposed me to things I might never have deliberately chosen to study. I can then take those concepts, research them further, build labs around them, create challenges from them, or decide that I never want to see them again:sweat_smile:.

By the end of this certification run, I didn't suddenly know everything, far from it. What I gained was exposure. I had a much clearer picture of the areas I enjoyed, the areas where I was weak, and the topics I wanted to go back and investigate properly.

Anyway, enough chit chat, let's talk certifications.

## CJCA - (RE) LEARNING THE BASICS
Full name: Certified Junior Cybersecurity Analyst

Going into CJCA, I had already been doing cybersecurity for a while, so it would have been very easy to look at a “junior” certification and assume I was past it. That was precisely why I wanted to do it. I didn't want to build the rest of this journey on top of fundamentals I thought I understood. And it turned out to be a genuinely solid introduction to cybersecurity.

There's no expectation that you're going to walk in chaining five vulnerabilities together, performing some obscure Active Directory wizardry, or summoning a shell through techniques discovered in an ancient forum post from 2012. That's not the point.

The course gives you exposure to the foundations of both offensive and defensive security. You start understanding not just how attackers approach systems, but also what defenders are looking for and why certain activity matters. And I think that's one of its biggest strengths.

If you're completely new to cybersecurity and still stuck on the eternal question of: “Should I do red team or blue team?”

CJCA gives you enough exposure to both sides to start forming an answer for yourself. You're not expected to already be an expert. You're there to build the foundation that everything else will eventually sit on. If I were starting my cybersecurity journey again, this is the kind of course I'd want near the beginning. Don't get me wrong, it won't turn you into an elite hacker overnight but it will make everything that comes afterwards make considerably more sense.

And then I moved on to web.

Things became... considerably less peaceful.


## CWES - COULD I HAVE DONE THAT WITH CURL?
Full name: Certified Web Exploitation Specialist
CWES did two things for me.
1. First, it gave me the confidence to seriously consider bug bounty hunting again.
2. Second, it made me realise just how badly I had been underutilising some of the tools I'd already been using.

There is a very particular kind of pain involved in learning a feature and immediately thinking, “You mean this tool could do this THE WHOLE TIME?”. That happened more than once. I already had some web penetration testing experience before starting CWES, so the concepts weren't completely alien to me. But the course helped connect things that I'd previously understood as separate vulnerabilities.

And that brings me to probably my biggest takeaway from CWES. **Stop looking at vulnerabilities in isolation**.

A vulnerability that looks relatively insignificant on its own can become much more interesting when combined with something else. Maybe one issue gives you information. Another gives you limited control. Another changes application behaviour. Individually? not that big of a problem but together moves your impact from low to high or critical.

CWES really reinforced that mindset of asking, “Okay, I found this. What does it allow me to do next?” instead of “I found XSS. Screenshot. Report. On to the next.”That shift in thinking was probably more valuable to me than memorising another collection of payloads.

It also changed how I approached tooling. Rather than treating Burp Suite and similar tools as things I already “knew,” I started paying more attention to the functionality I'd ignored because my existing workflow technically worked. Turns out technically works and efficient are two very different things.

The course also reinforced something that would come back to haun, I mean, help, me later during CPTS: Keep it simple. Sometimes the path forward isn't a ridiculously clever exploit. Sometimes you've already found everything you need and you're just refusing to connect the dots because you've convinced yourself the answer must be more complicated.

For someone with at least a little web security experience who wants to get better at understanding application behaviour, exploiting web vulnerabilities, and, most importantly, chaining them together, CWES was very worthwhile for me and gave me the confidence to try bug bounty again, tho I might be late to te party.

## PNPT - APPARENTLY, HACKING THE THINGS WASN'T ENOUGH
Full name: Practical Network Penetration Tester

PNPT was the odd one out in this HTB certification marathon, but it earned its cameo. I mainly took it because I wanted more exposure to Windows and Active Directory before attempting CPTS again. And it gave me exactly that, plus another serving of character development because...I failed my first attempt.

This one hurt differently from my 2023 CPTS disaster because, technically, I was much better. I could enumerate, find attack paths, exploit things and compromise machines. Surely that meant I knew how to conduct a penetration test? Apparently not. PNPT taught me that knowing how to hack machines and knowing how to conduct a pentest are two different things.

CTFs can get you accustomed to find vulnerability → exploit → get access → next machine. A whole lot of dopamine and adrenaline when you hit flow state. A pentest needs more. Your methodology, notes, evidence, reporting, and ability to explain what you did, matters just as much as getting access. My first attempt exposed weaknesses in that process. On the second, I approached the environment less like a collection of machines to compromise and more like an actual engagement. And this time, I passed.

I came to PNPT looking for more Windows and AD experience. I left with that, but also with a much more important question in my head, Not just “Can I compromise this?” but “Can I properly conduct and communicate a penetration test of this?”. 

With that lesson painfully acquired, there was only one thing left to do.

Go back to the exam that started this whole mess.

## CPTS - THE REMATCH
Full name: Certified Penetration Testing Specialist

Ah, CPTS.
![It's about to go down](kevin-hart-its-about-to-go-down.gif)

Sitting for this exam again felt a little like seeing an ex after three years, not one who wronged you, but one where the timing just wasn't right. You go your separate ways, grow a little, learn a few things, and eventually meet again thinking: “Okay... maybe this time we can make it work.”

Because if we're being fair to CPTS, it didn't do anything to me in 2023. I simply had no business being there. Six months into cybersecurity, zero flags on my first attempt and one on my second? The evidence speaks for itself.

Three years, several certifications and significantly more experience later, I was back. Surely the timing was better now.

Well...

It took me five days to get Flag 1. Now, I could blame work because I genuinely had a lot going on that first week, but if we're being fair, I also wasn't fully locked into the exam. Once I finally got that first flag, though, things started moving and for a while I thought: Okay. We might actually be cooking.

Then came **Flag 8**.
It took me three days!!

**THREE DAYS ON ONE FLAG.**
![img-description](dog-with-messed-up-hair.jpg)

At that point, I had made peace with failure. I was genuinely ready to submit whatever I had, take my retake, and call it character development but somehow, I eventually got past it and kept moving.

Then came my other terrible life choice: **the report.**

For most practical exams, I leave reporting until the last day or two. Is this recommended? Absolutely not. But between fighting the exam and fighting the report, I choose my battles. It had worked for CJCA and CWES because I take very detailed notes and enough screenshots that turning them into a report afterwards is usually straightforward. CPTS looked at that strategy and laughed.

I wrote a **200-page report in roughly 12 hours.** My fingers were on the verge of falling out, I swear. Even with detailed notes, that was mad business and something I absolutely **do not recommend**. If you're doing CPTS, set aside some time every day to update your report. Your future self will thank you.

CPTS was a *journey*, man. There were points where I was convinced I would be doing the whole thing again.

But after failing it twice back in 2023, finally seeing that **PASS** felt different.

It wasn't just another certification added to the collection.

It felt like closing a chapter I'd left unfinished three years ago.

**The rematch was finally over.**
![It's about to go down](yes-winning.gif)

## THE FOUR, HEAD TO HEAD

After all that, here's probably what most people actually came for.

If I had to put CJCA, CWES, PNPT and CPTS next to each other based purely on **my experience**, this is what the scoreboard looks like:

| | **CJCA** | **CWES** | **PNPT** | **CPTS** |
|---|---|---|---|---|
| **Best for** | Building/rebuilding cybersecurity fundamentals | Sharpening web exploitation | Learning practical pentest methodology, especially Windows/AD | Bringing everything together in a full pentest |
| **Difficulty for me** | Friendly | Challenging but manageable | Challenging | *Character development* |
| **Biggest lesson** | Don't assume the basics | Chain vulnerabilities; don't look at findings in isolation | Hacking machines ≠ conducting a pentest | Methodology, persistence and simplicity |
| **Reporting** | Manageable | Manageable | A major part of the experience | **WRITE. AS. YOU. GO.** |
| **What I walked away with** | Stronger foundations | Much more confidence in web + renewed bug bounty interest | Better AD exposure and pentesting discipline | Confidence that I could put everything together end-to-end |

Regarding price:
> At the time this blog was posted, a HTB silver annual subscription goes for $490. This package gives you access to all Tier II modules and below, 1 CJCA voucher which cannot be swapped with another exam and 1 exam voucher of your choice. What makes this even better is, you get access to the CWES, CDSA, COAE paths in full and part of the CWPE course, on top of other modules and skills paths that are not directly related to the exam of any of the certification paths. Although, it is worth noting that as of October 12th, the subscription will go for $550. For more info on price change, see [HTB New Academy Pricing](https://www.hackthebox.com/blog/new-academy-pricing). You can also check out Plans and subscriptions from your HTB academy account to see options like paying monthly for a student subscription, buying cubes to unlock modules or buying the exam vouchers directly if you have already covered the course content to see which plan works for you.

> As for PNPT, the course content bundle and exam voucher goes for $499 valid for a year. This comes with five courses: Practical Ethical Hacking (the main one you will need in my opinion), Open-Sorce Intelligence (OSINT) fundamentals, External Pentest Playbook, Windows Privilege Escalation for Beginners and Windows Privilege Escalation for Beginners. 

### BUT IF IT WERE MY MONEY...
There's one question I'd probably have if I were reading this:

**If you had to pay for everything yourself, what would you buy?**

Personally, I'd put my money toward an **HTB Academy Silver Annual subscription** before buying PNPT, and I am not saying this because I'm an ambassador:sweat_smile:.

Not because I think PNPT wasn't valuable, it absolutely was. It gave me more Windows/AD exposure and, more importantly, forced me to rethink the difference between compromising machines and actually conducting a professional penetration test. But when I look at **how I learn** and the amount of content I can work through, HTB Academy gives me more mileage for my money. That distinction matters because certifications are expensive, and “Which certification is better?” isn't always the most useful question.

Sometimes the better question is: **“What am I actually getting for the money I'm about to spend?”**

For me, structured access to a large library of content means I can learn beyond whichever certification I'm currently chasing. I can finish a path, realise I'm terrible at something, disappear into modules on that topic, build a lab around it, then come back.

PNPT gave me a valuable experience. HTB Academy better fits the way **I** learn. Your mileage, and your wallet, may vary.

---

## WHAT I ACTUALLY GOT OUT OF ALL THIS

Not badges.

Okay, that's a lie.

**The badges are nice.**

But the biggest thing I walked away with was confidence that's much more specific than it was at the beginning of the year.

I know where I'm comfortable. I know where I struggle. I know which rabbit holes I want to disappear into next, and I'm much better at recognising when I actually understand something versus when I've just seen it enough times to *think* I understand it.

The sequential approach did exactly what I wanted it to do. And, most importantly, CPTS finally closed the loop that 2023-me opened and couldn't finish.

---

## IF YOU'RE STARTING THIS PATH

Go sequential if free-form learning tends to lose you too. There's no shame in needing structure, figuring out *how* you learn is part of learning.

Take ridiculously detailed notes and screenshots. Future-you writing the report will appreciate present-you immensely.

And if you're doing anything CPTS-sized:

**WRITE THE REPORT AS YOU GO.**

I don't care how beautiful your notes are. I don't care how many screenshots you took. I don't care how convinced you are that you'll “just put everything together on the last day.” Learn from my suffering.

Finally, don't let one stubborn flag convince you that the entire attempt is doomed. It took me five days to get Flag 1 and another three days to get Flag 8. At both points, it would have been very easy to decide I simply wasn't getting through the exam.

Eventually, both gave way. Sometimes you're missing a technique. Sometimes you're overcomplicating something.

And sometimes you just need to touch grass, come back, and look at the same information with a slightly less offended brain.

