# rest
Remote Exploit Scan Tool <br /> 
Use SSH credentials to remotely scan linux system <br />
packages for known exploits in Exploit-DB and run <br />
basic enumeration scripts. <br />

Currently works against Debian and RHEL based systems. <br />
Bug testing, additions, and rewrites are welcome, just submit an issue or pull request. <br />
Thanks to mikesz81 for concept and nbulischeck for code review. <br />

## Dependencies

* linux (tested in kali-2019.2)
* searchsploit
* python>=3.6
* pip
    * termcolor >= 1.1.0
    * paramiko >= 2.6.0

> **Note:**
> It is recommended to git clone this repository into a python virtual <br /> 
> envirnment and run `pip install -r requirments.txt`

## Usage

```
usage: rest.py [-h] [-n [port_number]] [-p password] [-k key_file] [-le]
               hostname username

positional arguments:
  hostname          hostname or IP address of remote machine
  username          username used to login to host.

optional arguments:
  -h, --help        show this help message and exit
  -n [port_number]  port number (default is 22).
  -p password       password for user.
  -k key_file       location of RSA or DSA Key file
  -le               run LinEnum.sh and return LE_report
```

Examples:

`./rest.py 192.168.1.100 vera -p eatadick6969 -n 666` <br />
`./rest.py 192.168.1.101 jeff -p my_name_a -k ~/.ssh/id_rsa` <br />
`./rest.py 192.168.1.102 bigwillystyle -k ~/.ssh/id_rsa` <br />
`./rest.py 192.168.1.103 chuck -p nbuck -le`
