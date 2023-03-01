# kryptogramm

Tool for individual vote verification at Internet enabled parliament elections in Estonia 2023. Since we are allowed to verify our vote only up to 30 minutes after casting, we have to make this time really special, don't we?

Usage:

```
./kryptogramm.py qr-code.jpg
```

![Running the tool](demo.png)

## What you get

Estonian Internet voting has individual verification up to 30 minutes from casting the vote. This is done by downloading cryptogram from vote collection server and decrypting it with ElGamal ephemeral key. Usually you don't get the cryptogram out of proprietary voting application but by default also not from the verification application. With this tool you:

* Download encrypted ballot for keeping for as long as you want
* Decrypt your encrypted ballot and see who you voted for
* Get to understand better how Internet voting works

See the details about [vote verification](https://www.valimised.ee/et/e-haaletamine/e-haaletamisest-lahemalt/haaletamise-kontroll-nutitelefoniga) on [Estonian electoral commission web page](https://www.valimised.ee/et/e-haaletamine/dokumendid) or check out source code of the [official verification tool](https://github.com/vvk-ehk/ivotingverification).

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
pip install dist/kryptogramm-0.0.1.tar.gz
```
## But why?

If you like this tool, you may also want to check out [Pseudovote](https://github.com/infoaed/pseudovote)!
