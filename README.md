# rest

Remote Exploit Scan Tool <br /> 
Use SSH credentials to remotely scan linux system <br />
packages for known exploits in Exploit-DB and run <br />
basic enumeration scripts. <br />

Currently works against Debian and RHEL based systems. <br />
Bug testing, additions, and rewrites are welcome, just submit an issue or pull request. <br />
Thanks to mikesz81 for concept and nbulischeck for code review. <br />
Addded jaws-enum.ps1 for windows systems. <br />

## Dependencies

* linux (tested in kali-2019.2)
* searchsploit
* python>=3.7
* pip
    * termcolor >= 1.1.0
    * paramiko >= 2.6.0

> **Note:**
> It is recommended to clone this repository into a python virtual <br /> 
> envirnment and run `pip install -r requirements.txt`

## Usage

```
usage: rest.py [-h] [-n [port_number]] [-p password] [-k key_file] [-ss] [-le]
               [-t] [-ps] [-js]
               hostname username

positional arguments:
  hostname          hostname or IP address of remote machine
  username          username used to login to host

optional arguments:
  -h, --help        show this help message and exit
  -n [port_number]  port number (default is 22)
  -p password       password for user
  -k key_file       location of RSA or DSA Key file
  -ss               run package list against searchsploit database
  -le               run LinEnum.sh and return LE_report
  -t                add thorough switch to -le LinEnum.sh
  -ps               run pspy64 or pspy32 with defaults and return pspy_out
  -js               run jaws-enum.ps1 and return jaws-report
```

Examples:

`./rest.py 192.168.1.100 vera -p eatadick6969 -n 666` <br />
`./rest.py 192.168.1.101 jeff -p my_name_a -k ~/.ssh/id_rsa -ss` <br />
`./rest.py 192.168.1.102 bigwillystyle -k ~/.ssh/id_rsa` -ss <br />
`./rest.py 192.168.1.103 buck -p nchuck -le` <br />
`./rest.py 192.168.1.104 matt_a -p i_love_ben_a -ps` <br />
`./rest.py 192.168.1.105 ben_a -p i_love_matt_d -ss -le -t -ps` <br />
`./rest.py 192.168.1.106 administrator -p password123 --js` <br />
