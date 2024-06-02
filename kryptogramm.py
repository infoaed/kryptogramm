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
        ('params', Integer),
        ("vote",  Integer)
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
MIIDMjCCAaAGCSsGAQQBl1UCATCCAZECggGBAP//////////yQ/aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue1SkHcJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1xV3wb0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKqsQtrTMXDQRQejOoVSGr3xy6ZOz7hQRY2+8KiupxV10GDH2zlw+FpuHkx6v1rozbCTPXHoyU4EolYZ3O49ImGtLua/Ev+gbZighk2HYCcz7IamRSHysYF3sgDLvhF1d6YV1sdwmIwLrZRuII4k+gdOWrMUPbW/zg/RCOS4LRIKk60sr//////////wIBAhsHRVBfMjAyNAOCAYoAMIIBhQKCAYEA6LMFRnvHNQzrlbIW4kIY++ZUNhgoN7YVNuLdzLIx2FP1n9CeSxh2Bl/jzIkjreuFlSePZT5PY4gvBlN1RJPFlDTVR2N9tQRmPVCk/3Hf7UPqpBT7dszqm4Rs5qjjgxK4r+xi2PBFhJPpCpZWumFS7oVabAmnXjBq+Tpbk9LpKnFIQo1rxwnP2d5ycS07elPPUfC4EJbXanky/W7dBC+TAWfHb6cVur+tzDYfDDutD26Z9wjPG2EZPaAhkAD31qdKB7uajCLBFN4Qd3elI21GXYWa8TrMBvu1WtJKDOKhtKcStGnOP/a3dm/9ZzCxemN3XSMNsPQ2ag/O0tU5gd8JfKqAXsYkX8IZg5vV3mCLtc+bPaF0D5SyJ2+doAV526UOPZAY7RRyooGcj2pqyDMfRV3Lj/cJNy1dIPla6JlK0NWU34yOHMUe9IcX95Ep47Jdcy1kcT8HOGhdh2UPlA03rXeHbH6rb+otk7AmjOnf9wQFAHohUNmMk49FhJH6sE5t
-----END PUBLIC KEY-----"""

reg_cert = """-----BEGIN CERTIFICATE-----
MIIDkTCCAnmgAwIBAgIUMNFEZ0iDkFDfB3W8BwEUayJOrgkwDQYJKoZIhvcNAQELBQAwWDELMAkGA1UEBhMCRUUxDDAKBgNVBAoMA1JJQTEaMBgGA1UECwwRSVZYViBDZXJ0aWZpY2F0ZXMxHzAdBgNVBAMMFkNvbGxlY3RvciBSZWdpc3RyYXRpb24wHhcNMjQwNDE4MDg0OTMxWhcNMjUwNDE4MDg0OTMxWjBYMQswCQYDVQQGEwJFRTEMMAoGA1UECgwDUklBMRowGAYDVQQLDBFJVlhWIENlcnRpZmljYXRlczEfMB0GA1UEAwwWQ29sbGVjdG9yIFJlZ2lzdHJhdGlvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANcWk0AL2qEiSm+c5HiWAL92bqiV1qlqwbxEV7UlwvjfZ8McmqTEwdRDyOSZtpTmYHFns1m8KEg27I84K3enUcp5EdYKHGCXJJOb6gvB5314qhyEFn5GY2JqdK8FEt6ovWyTZU5zvvVrFmHZhyEDH34v8hw20LM0H9Ahja0BCR+IPL+PJuDwT+M0YXj14TmDQ6fOQNFtb12p0CsRn+f9pNHh/c3dyhZQy7EVfcyksmcT/+bjMWzNw6WkpWEBVllaXo/O/AZqyKD6XsktY4cksWnZOJW4C4VP7i3SHwEFR2XiQFFDylkbyGT5C3S48SNOOttiMboGUm2jlJQQe/FgDvkCAwEAAaNTMFEwHQYDVR0OBBYEFOY4dnf+Ukhy6m50N5GlOn913l1tMB8GA1UdIwQYMBaAFOY4dnf+Ukhy6m50N5GlOn913l1tMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAEiwAcqONnOHJq2IeKNQDz1bx4Sc2cp9y/tMpRbsrIXKzkTbYDzV1vpWFkC4tlfX36xvl/FM4Wa/ZmSrmhgeIlD0aDKzAr2MQdYhSSYw11xzYIIzCu/a6KUoXnLstxTk5ZU6VG0McMtZy5lrI+wAzyk1UYKK2++j7FaPltgyg+zhWllUbC3QnnvcxKK9piruykbIBKSAuPEEy7Y489FX3GAxM7snbcJ5V2njk1PduQtdDWbDiV9EHat314jiygwgstWes6rAUZA8+HIoARKPzDE10nbqO2NpxSbWuotxyRX4OBUTNjLmcoc/IKe6j8+yKswqJpaKTRgaiTOL2EhpXr4=
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
        print("ISIKLIKU HÄÄLE KONTROLLRAKENDUS @e-hääletus #RK2023\n")
        print("Kasuta:")
        print("\tkryptogramm <pildifail,*/voteid.json> [jõuvõte?]")
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
