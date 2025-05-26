# kryptogramm

Tool for individual vote verification at [Internet enabled](https://github.com/vvk-ehk/ivxv) parliament elections in Estonia. Since we are allowed to verify our vote only up to 15 minutes after casting, we have to make this time really special, don't we?

Usage:

```
./kryptogramm.py (<QR-CODE.jpg> | <VOTE.json>) [--force-download]
```

[![Running the tool](https://img.youtube.com/vi/JX2NiK_p6wo/0.jpg)](https://www.youtube.com/watch?v=JX2NiK_p6wo)

## What you get

Estonian Internet voting uses individual vote verification up to 15 minutes from [casting the vote](https://youtu.be/GuKiJKL4WdI). Technically, this is done by downloading cryptogram from vote storage server and decrypting it with ElGamal ephemeral key created during encryption at the voting phase. Vote identificator and keys needed for decryption are passed on to secondary device by QR code. Usually you don't get the cryptogram out of proprietary voting application but by default also not from the verification application. With this tool you will get to:

* Decode the QR code encapsulating ElGamal key and vote ID
* Download encrypted ballot for keeping for as long as you want
* Decrypt your encrypted ballot and see who you voted for
* Inspect vote container, signature, registration receipts etc
* Convert downloaded vote into valid digitally signed container
* Transparency of human readable/editable Python 300-liner
* Get to understand better how Internet voting works

Election servers also limit verification by three attempts per ballot. By using the tool you get full control of the democratic process, you can audit every part of it and make it fit your personal preferences or requirements of digital democracy. Currently that kind of hands on auditing is possible only for very limited parts of the election process.

See the details about [vote verification](https://www.valimised.ee/en/internet-voting/guidelines/checking-i-vote) on Estonian electoral commission [web page](https://www.valimised.ee/en/internet-voting/documents-about-internet-voting) (documentation mostly in Estonian) or check out source code of the [official verification tool](https://github.com/vvk-ehk/ivotingverification).

You can use [sample data from two elections](data) to give the tool a test run.

## Installation instructions

```
git clone https://github.com/infoaed/kryptogramm.git
cd kryptogramm
pip install -r requirements.txt
```

You might also need:

```
sudo apt-get install libzbar0
```

But you might also go directly:

```
sudo apt-get install python3-zbar
```

And if you'd like to run this as a command line tool:

```
hatch build
pip install dist/kryptogramm-0.2.0.tar.gz
```
## But why?

In combination with the voting application prototype the tool was used to conduct [close inspection of voting protocol](https://gafgaf.infoaed.ee/en/posts/perils-of-electronic-voting/#independent-vote-verification-tool) during parliamentary elections and appeared [useful for detecting and reporting anomalies](https://infoaed.ee/ballot2023) as well as [demonstrating vote secrecy breach](https://infoaed.ee/proof2023).

There is also a draft report "[Votes without ballots: e‑voting at 2023 elections in Estonia](https://gafgaf.infoaed.ee/en/posts/votes-without-ballots/)", which was under title "[Should e-voting experience of Estonia be copied?](https://media.ccc.de/v/37c3-12298-should_e-voting_experience_of_estonia_be_copied)" presented at the [Chaos Communication Congress 2023](https://fahrplan.events.ccc.de/congress/2023/fahrplan/events/12298.html). The report is still edited and is easiest to approach through [summary of the findings](https://infoaed.ee/findings2023/).

You may get better picture of my projects by having look at this unfinished [netizen index of e-voting requirements](https://debriif.infoaed.ee/docs/draft-list/) and civil society organisation [Fair Elections Estonia](https://ausadvalimised.ee/en/), advocating for observability of e-voting.

If you like this tool, you may also want to check out [Pseudovote](https://github.com/infoaed/pseudovote), another of my digital democracy tools.
