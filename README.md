# kryptogramm

Tool for individual vote verification at Internet elections in Estonia 2023. Since we are allowed to verify our vote only up to 30 minutes after casting, we have to make this time really special, don't we?

Usage:

```
./kryptogramm qr-code.jpg
```

Installation instructions:

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

If you like this tool, you may also want to check out [Pseudovote](https://github.com/infoaed/pseudovote)!