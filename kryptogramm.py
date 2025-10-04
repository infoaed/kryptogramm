#!/usr/bin/env python3

import json, base64
import io, sys, random
import socket, ssl

from asn1crypto.core import Sequence, Integer, BitString, OctetString
from asn1crypto.cms import ContentInfo
from asn1crypto.algos import AnyAlgorithmIdentifier, SignedDigestAlgorithm

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from tinyec import registry
from tinyec.ec import Point

from pyasice import Container
from pyasice.ocsp import OCSP
from pyasice.tsa import TSA

from lxml import etree

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
        ('c1', OctetString),
        ("c2",  OctetString)
    ]

class IVXVBallot(Sequence):
    _fields = [
        ("data", AnyAlgorithmIdentifier),
        ('content', IVXVContent)
    ]

class IVXVSignature(Sequence):
    _fields = [
        ("algo_id", SignedDigestAlgorithm),
        ('signature', OctetString)
    ]

nec_pub = """-----BEGIN PUBLIC KEY-----
MIGIMB4GCSsGAQQBho0fATARGwVQLTM4NBsIS09WXzIwMjUDZgAwYwRhBPHtodZe9e2rpZfQGlm2FB44gtMQKU3kre3LfuPeHxp+OUa1p/X7JDw/1HHqSrWuDTnWrh3aNttN5w0YC5c1pGu4gqv80KDXbGxJ36lLF/HF+z3Lm6w4JQ0Tk8AyxX4ZfQ==
-----END PUBLIC KEY-----"""

reg_cert = """-----BEGIN CERTIFICATE-----MIIDkTCCAnmgAwIBAgIUV9BjJbf1G9Z4VGriXUqydi8Nlw0wDQYJKoZIhvcNAQELBQAwWDELMAkGA1UEBhMCRUUxDDAKBgNVBAoMA1JJQTEaMBgGA1UECwwRSVZYViBDZXJ0aWZpY2F0ZXMxHzAdBgNVBAMMFkNvbGxlY3RvciBSZWdpc3RyYXRpb24wHhcNMjUwOTE4MDkxMTQ0WhcNMjYwOTE4MDkxMTQ0WjBYMQswCQYDVQQGEwJFRTEMMAoGA1UECgwDUklBMRowGAYDVQQLDBFJVlhWIENlcnRpZmljYXRlczEfMB0GA1UEAwwWQ29sbGVjdG9yIFJlZ2lzdHJhdGlvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANemYp5xc0W8ImDP33c9IUcCcIS+EgkhZ4tQBTY5O7kKbmz5MhLk++1RDukx1ZtZIi9RrlNQD6iiuFLYao5R03qtzhnMAXrwP4LJwfrinW0K6IkKzQX827RgcHteTlEy352XcIE7jFmk3YMO9L2lgu2zZvKOAarAbBgtgK0H3dmqn4rPuDGQhB+xZBNjMjf2AkoAiYDKSQRZ2Nd6pkBicXesqPeqCubjPooDO4lWvRRHbVtICraXoaPViBTcXJEeEhReQUpIPDOJ5180TWna3BzsPlnfMaweuOc3A2P4rQuc6RtzLjzxkT+yyaY6zRfzfqJyeri8RRCtXuXX9dsCSGsCAwEAAaNTMFEwHQYDVR0OBBYEFA3cecUuQwFdfKRV3EViVrb/YVUvMB8GA1UdIwQYMBaAFA3cecUuQwFdfKRV3EViVrb/YVUvMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABtmiDoN/bzFNv7Pkawj7uLT2nyO0DQL+GarBjWqjSJP+14AaaC0Oy+A7zcvX/6W/IQxo5zB4Cch5W21O95E8bScGcqSxtle2ZR1Epf4mKpbx6RMfVGiOK1uhWmhniFx8qPJSCds3taPtsKoG/m7ksDAj29rqZTEciYPY4rgQZoc2VMYWbK36oDbcqy0PcwGjbBofZbAehxXlzBInFIT595onOI057vtbnCg1ULMY9P09u7gkIR/AJrU+q2AfsnaSHpVvuNrKX97prmTfzHMmHjvGJyiXpjFed+ZVMd9CFU2OAa92OlEIXvA6um2Mv1I6gYKLL5ozhVX8TY73q7Sdr0=
-----END CERTIFICATE-----"""

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
        print("ISIKLIKU HÄÄLE KONTROLLRAKENDUS @e-hääletus #KOV2025\n")
        print("Kasuta:")
        print("\tkryptogramm (<QR-CODE.jpg> | <VOTE.json>) [--force-download]\n")
        exit(1)

    archive_mode = args[0].strip().lower().endswith(".json")
    forced_mode = len(args) > 1

    vote = voteid = jsres = container = ephkey_bin = None

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
        if ephkey_bin is None:
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

        fn = container.data_file_names[0]
        f = container.open_file(ballot_name)
        ballot = f.read()
        for xmlsig in container.iter_signatures():
            jsres["BallotMoment"] = xmlsig.get_signing_time()

        asc_ballot = base64.b64encode(ballot).decode()

        with open(votesafe + ".asice", 'wb') as bin_file:
            bin_file.write(vote)
        jsres[fn] = asc_ballot
        jsres["Ephemeral"] = qr["ephkey"]
        jsres["VoteID"] = voteid
        with open(votefile, 'w') as outfile:
            json.dump(jsres, outfile, sort_keys=True, indent=4)

    # check integrity/qualification proofs
    container.verify_container()
    sigs = container.signature_file_names
    if len(sigs) != 1:
        fail("vähem või rohkem kui üks allkiri")
    sig, sig_file = next(container.iter_signatures_with_filenames())

    ocsp_bin = OCSP.load(base64.b64decode(jsres["result"]["Qualification"]["ocsp"]))
    sig.set_ocsp_response(ocsp_bin)
    sig.verify_ocsp_response()

    tspreg_bin = base64.b64decode(jsres["result"]["Qualification"]["tspreg"])
    sig.set_timestamp_response(TSA.load(tspreg_bin))
    sig.verify_ts_response()

    sig.verify()

    tspreg = ContentInfo.load(tspreg_bin)
    nonce = tspreg["content"]['encap_content_info'].native['content']['nonce']
    nonce_sig = IVXVSignature.load(nonce.to_bytes((nonce.bit_length() + 7) // 8, 'big'))

    msg_canonical = etree.tostring(sig._get_signature_value_node(), method="c14n")
    reg_pub = load_pem_x509_certificate(str.encode(reg_cert)).public_key()
    reg_pub.verify(nonce_sig['signature'].native, msg_canonical, padding.PKCS1v15(), hashes.SHA256())

    container.update_signature(sig, sig_file)
    container.save(votesafe + "_qualified.asice")

    # data seems valid, attempt decryption
    m = None

    bin_key = base64.standard_b64decode("".join(nec_pub.split("\n")[1].strip().split()))
    d = IVXVKey.load(bin_key).native

    if d["data"]["algorithm"] == "1.3.6.1.4.1.3029.2.1":
        print("kasuta tööriista versiooni 0.1.*")
    elif d["data"]["algorithm"] != "1.3.6.1.4.1.99999.1":
        print("tundmatu avalik võti")

    c = registry.get_curve("secp384r1")
    key = d["key"]
    key_x = sum(v<<i for i, v in enumerate(key[len(key)-2*384:-384][::-1]))
    key_y = sum(v<<i for i, v in enumerate(key[len(key)-384:][::-1]))
    eph_key = int.from_bytes(ephkey_bin, 'big')

    b = IVXVBallot.load(ballot)["content"].native

    print(isoparse(jsres["BallotMoment"]).astimezone(), d["data"]["parameters"]["1"])
    print(f"\n{asc_ballot}\n")

    pub = Point(c, key_x, key_y)
    c1 = Point(c, int.from_bytes(b["c1"][1:49]), int.from_bytes(b["c1"][49:]))
    c2 = Point(c, int.from_bytes(b["c2"][1:49]), int.from_bytes(b["c2"][49:]))

    if c.g * eph_key != c1:
        fail("võltsitud krüptogramm")
   
    mp = c2 - eph_key * pub

    m = (mp.x>>2).to_bytes(((mp.x>>2).bit_length() + 7) // 8, 'big')

    with open(votesafe + "_" + ballot_name, 'wb') as bin_file:
        bin_file.write(m)

    if len(m) != 48:
        fail("vale pikkus")

    if m[0] != 0x1f:
        fail("formaadi algus vale")

    m = m[1:]

    m = m.lstrip(b"\xff")
    
    if m[0] != 0xfe:
        fail("sedeli algus vale")

    m = m[1:].decode("latin_1")
        
    for i in range(0, len(m)):
        print(f"\033[1m{m[i]}\033[0m", end="  ")
    print()
    for i in range(0, len(m)):
        print("{:02X} ".format(ord(m[i])), end="")
    print("\n", flush=True)
        
    print("ÜTLE KRÜPTOGRAMM! 🙊")

if __name__ == "__main__":
    sys.exit(main())
