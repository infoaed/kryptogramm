#!/usr/bin/env python3

import json, base64
import io, sys, random
import socket, ssl

from asn1crypto.core import Sequence, Integer, BitString
from asn1crypto.algos import AnyAlgorithmIdentifier

from pyasice import Container

from PIL import Image
from pyzbar.pyzbar import decode, ZBarSymbol

from platform import platform
from dateutil.parser import isoparse
from pathlib import Path

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

class IVXVKey(Sequence):
    _fields = [
        ("data", AnyAlgorithmIdentifier),
        ('key', BitString)
    ]

class IVXVContent(Sequence):
    _fields = [
        ('params', Integer),
        ("vote",  Integer)
    ]

class IVXVBallot(Sequence):
    _fields = [
        ("data", AnyAlgorithmIdentifier),
        ('content', IVXVContent)
    ]

pub = """-----BEGIN PUBLIC KEY-----
MIIDMjCCAaAGCSsGAQQBl1UCATCCAZECggGBAP//////////yQ/aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue1SkHcJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1xV3wb0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKqsQtrTMXDQRQejOoVSGr3xy6ZOz7hQRY2+8KiupxV10GDH2zlw+FpuHkx6v1rozbCTPXHoyU4EolYZ3O49ImGtLua/Ev+gbZighk2HYCcz7IamRSHysYF3sgDLvhF1d6YV1sdwmIwLrZRuII4k+gdOWrMUPbW/zg/RCOS4LRIKk60sr//////////wIBAhsHUktfMjAyMwOCAYoAMIIBhQKCAYEAwcYXpWjSJQrLA4L4HhWT7cnZ0vnnOmgkf8lJ5kMF8qQo8TYQl2krlEoewlnTrjdTgLTnPbOQeryURGuiVGE6zhYMUeNaTPi55LthNRRWXF2W7hmXVQqQGcIpQsaciXTfLUhLBsZ7Z4eMIwAmYwkfY9FMowyFzMBkuCmO1Ab2ZqbVlikpNbaf6QpgVXTLM0yjMklb2PX5xPbAIgcmiGeOcVS5R5deIajmc06KHSwjdRdlRdbUZ4SkuDyZLGhp+M+NJ0rjAYpWi9ub40LkCI1LQ2kCpNyxZIpI+I7xik7D8DUhqwW2aftKV+L8OOWrIi2Vtmq14kOhT4wKhKDlsoFeJ5XqyG4j0/Yfj0qVXkKzMnhLyQXyV/dk1ejjvK9Fu91ti9KF/HpgBFhVEpKNhSn1oLQYxSVo9n4aQkq9BPkzKZwc1cGZCMaWbk/9lpibcfyeqRLgUP/5coj7KEasl38Nu6ROZzq8Cn63i/UUz0rSrR8fLlFI3jiR6hPRZ/a4xJok
-----END PUBLIC KEY-----"""

sni = "verification.ivxv.valimised.ee"
verify_urls = ["koguja1.valimised.ee:443", "koguja2.valimised.ee:443", "koguja3.valimised.ee:443"]

def fail(reason):
    print("SEDEL EI VASTA NÕUETELE!\n")
    print(f"({reason})")
    exit(1)

def main(args=None):
    if args is None:
        args = sys.argv[1:]

    if len(args) == 0:
        print("ISIKLIKU HÄÄLE KONTROLLRAKENDUS @e-hääletus #RK2023\n")
        print("Kasuta:")
        print("\tkryptogramm <pildifail,*/voteid.json> [jõuvõte?]")
        exit(1)

    archive_mode = args[0].strip().lower().endswith(".json")
    forced_mode = len(args) > 1

    vote = voteid = jsres = container = None

    if not archive_mode: # normally try qr code first
        img = Image.open(args[0])
        gfx = decode(img)

        if len(gfx) == 0:
            print("POLE VIST QR-KOODI?")
            exit(1)

        elif gfx[0].type == 'QRCODE':
            d = gfx[0].data.split()
            
            qr = {
                "sessid": d[0].decode(),
                "ephkey": d[1].decode(),
                "voteid": d[2].decode()
                }

        voteid = qr["voteid"]
        sessionid = qr["sessid"]
        ephkey_bin = base64.standard_b64decode(qr["ephkey"])

        votesafe = voteid.replace("/","_")
        votefile = votesafe + ".json"

    else: # init loading ids from json
        votesafe = args[0][0:-len(".json")]
        votefile = args[0]

    path = Path(votefile)

    if path.is_file(): # use json for data, if exists
        with open(votefile) as vote_json:
            jsres = json.load(vote_json)
            
        voteid = jsres["VoteID"]
        sessionid = jsres["result"]["SessionID"]

    if not forced_mode and jsres is not None: # we have json
        print(f"OLEMASOLEVA '{voteid}' kasutamine\n")

        vote = base64.standard_b64decode(jsres["result"]["Vote"])
        ephkey_bin = base64.standard_b64decode(jsres["Ephemeral"])

        container = Container(io.BytesIO(vote))
        ballot_name = container.data_file_names[0]

        asc_ballot = jsres[ballot_name]
        ballot = base64.standard_b64decode(asc_ballot)
        
        print("🗳️   ", end="", flush=True)

    else: # did not have json or download was forced
        random.shuffle(verify_urls)
        context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
        context.load_default_certs()

        verify = {
            "id": 1,
            "method": "RPC.Verify",
            "params": [{
                "OS": platform(aliased=True),
                "SessionID": sessionid,
                "VoteID": voteid
            }],
        }

        s = socket.socket(socket.AF_INET)
        ssl_sock = context.wrap_socket(s, server_hostname=sni)

        url = verify_urls[0]
            
        url, port = url.split(":")
        port = int(port)
        print(f"UHENDUMINE {sni} @{url}:{port}\n")

        ssl_sock.connect((url, port))
        payload = json.dumps(verify)
        cnt = ssl_sock.send(payload.encode())

        response = b''
        while True:
            data = ssl_sock.recv(1024)
            print(">", end="", flush=True)
            response += data
            if not data:
                ssl_sock.shutdown(socket.SHUT_RDWR)
                ssl_sock.close()        
                break

        jsres = json.loads(response.decode())
        if len(response) > 5000 and "result" in jsres and "Vote" in jsres["result"]:
            vote = base64.b64decode(jsres["result"]["Vote"])
            print(" 🗳️   ", end="", flush=True)
                
        if not vote:
            print(" ❌ \n\nEI SAANUD KÄTTE HÄÄLT!")
            exit(1)

        container = Container(io.BytesIO(vote))
        ballot_name = container.data_file_names[0]

        f = container.open_file(ballot_name)
        ballot = f.read()
        for xmlsig in container.iter_signatures():
            jsres["BallotMoment"] = xmlsig.get_signing_time()

        asc_ballot = base64.b64encode(ballot).decode()

        with open(votesafe + ".bdoc", 'wb') as bin_file:
            bin_file.write(vote)
        jsres[fn] = asc_ballot
        jsres["Ephemeral"] = qr["ephkey"]
        jsres["VoteID"] = voteid
        with open(votefile, 'w') as outfile:
            json.dump(jsres, outfile, sort_keys=True, indent=4)

    # have the data, attempt decryption
    m = None

    bin_key = base64.standard_b64decode("".join(pub.split("\n")[1].strip().split()))
    d = IVXVKey.load(bin_key).native

    key = sum(v<<i for i, v in enumerate(d["key"][72:][::-1]))
    
    p, g, id = (d["data"]["parameters"][x] for x in d["data"]["parameters"])
    q = p >> 1

    b = IVXVBallot.load(ballot)["content"]["vote"].native
    p = int(p)
    q = int(q)
    eph = int.from_bytes(ephkey_bin, 'big')

    print(isoparse(jsres["BallotMoment"]).astimezone(), f"({id})")
    print(f"\n{asc_ballot}\n")

    f = pow(key, eph, p)
    fi = pow(f, -1, p)
    s = fi * b % p

    if pow(s, q, p) == 1:
        m = p-s if s>q else s

    if not m:
        fail("krüptogramm ei avanenud")

    m = m.to_bytes((m.bit_length() + 7) // 8, 'big')

    with open(votesafe + "_" + ballot_name, 'wb') as bin_file:
        bin_file.write(m)

    if len(m)+1 != p.bit_length() / 8:
        fail("vale pikkus")

    if m[0] != 1:
        fail("formaadi algus vale")

    m = m[1:]

    m = m.lstrip(b"\xff")

    if m[0] != 0:
        fail("sedeli algus vale")
        
    m = m[1:].decode("UTF-8")

    j = 0
    while j < len(m):
        i=j
        while i < len(m) and ord(m[i]) != 0x1f:
            print(f"\033[1m{m[i]}\033[0m", end="  ")
            i+=1
        print()
        i=j
        while i < len(m) and ord(m[i]) != 0x1f:
            print("{:02X} ".format(ord(m[i])), end="")
            i+=1
        if i < len(m) and ord(m[i]) == 0x1f:
            print("{:02X} ".format(ord(m[i])), end="")
        print("\n", flush=True)
        if i >= len(m):
            break
        j=i+1
        
    print("ÜTLE KRÜPTOGRAMM! 🙊")

if __name__ == "__main__":
    sys.exit(main())
