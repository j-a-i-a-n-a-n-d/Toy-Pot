#================================================packages used ==========================================================================
import argparse
import threading
import socket 
import sys
import traceback
import logging
import paramiko
from binascii import hexlify
from paramiko.py3compat import b, u, decodebytes
#========================RSA KEY generated via ssh-keygen -t rsa -f server.key=========================================================
HOST_KEY = paramiko.RSAKey(filename='server.key')
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"

UP_KEY = '\x1b[A'.encode()
DOWN_KEY = '\x1b[B'.encode()
RIGHT_KEY = '\x1b[C'.encode()
LEFT_KEY = '\x1b[D'.encode()
BACK_KEY = '\x7f'.encode()

#==============================================logging file=================================================================================
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',level=logging.INFO,filename='ssh_honeypot.log')

#=========================================handling request from the client=================================================================
def handle_cmd(cmd, chan, ip):
    response = ""
    if cmd.startswith("dir"):
        f=open("sample.txt", "r")
        response=f.read()
        print(response)
        f.close()
    elif cmd.startswith("cd"):
        response = "/root/user"

    if response != '':
        #logging
        logging.info('Response -> honeypot ({}) {}'.format(ip,response))
        response = response + "\r\n"
    chan.send(response)
#=========================================================================================================================================
#=========================================================================================================================================
class BasicSshHoneypot(paramiko.ServerInterface):

    client_ip = None

    def __init__(self, client_ip) :      #constructor
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        #logging
        logging.info('client called check_channel_request ({}): {}'.format(
                    self.client_ip, kind))
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        #logging
        logging.info('client called get_allowed_auths ({}) with username {}'.format(
                    self.client_ip, username))
        return "publickey,password"

    def check_auth_publickey(self, username, key):
        fingerprint = u(hexlify(key.get_fingerprint()))
        #logging
        logging.info('client public key ({}): username: {}, key name: {}, md5 fingerprint: {}, base64: {}, bits: {}'.format(
                    self.client_ip, username, key.get_name(), fingerprint, key.get_base64(), key.get_bits()))
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL        


#=======================================accepting all credentials as correct===============================================================
    def check_auth_password(self, username, password) :
        logging.info('new client credentials ({}): username: {}, password: {}'.format(
                    self.client_ip, username, password))
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command_text = str(command.decode("utf-8"))
        handle_cmd(command_text,channel,self.client_ip)
        logging.info('client sent command via check_channel_exec_request ({}): {}'.format(
                    self.client_ip,command))
        return True
#========================================================================================================================================
#========================================================================================================================================


#==========================================handling the connections =====================================================================
def handle_connection(client, addr):

    client_ip = addr[0]
    logging.info('New connection from: {}'.format(client_ip))

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        transport.local_version = SSH_BANNER # Change banner to appear more convincing
        server = BasicSshHoneypot(client_ip)
        try:
            transport.start_server(server=server)
#==========================happens if we are not on the command line ===============================================================
        except paramiko.SSHException:
            print('SSH failed.')
            raise Exception("\nSSH failed")

        # wait for auth
        chan = transport.accept(10)
        if chan is None:
            print(' No channel (from '+client_ip+').')
            raise Exception("No channel")
        
        chan.settimeout(10)

        if transport.remote_mac != '':
            logging.info('Client mac ({}): {}'.format(client_ip, transport.remote_mac))

        if transport.remote_compression != '':
            logging.info('Client compression ({}): {}'.format(client_ip, transport.remote_compression))

        if transport.remote_version != '':
            logging.info('Client SSH version ({}): {}'.format(client_ip, transport.remote_version))
            
        if transport.remote_cipher != '':
            logging.info('Client SSH cipher ({}): {}'.format(client_ip, transport.remote_cipher))

        server.event.wait(10)
        if not server.event.is_set():
            logging.info('** Client ({}): never asked for a shell'.format(client_ip))
            raise Exception("No shell request")
     
        try:
            chan.send("Welcome to Dell Inspiron 3593 DESKTOP-42P1AH3 \nOS info : Windows 10.0 Home Edition\r\n\r\n")
            run = True
            while run:
                chan.send("$/root/user ")
                command = ""
                while not command.endswith("\r"):
                    transport = chan.recv(1024)
                    print(client_ip+"- received:",transport)
                    # Echo input to psuedo-simulate a basic terminal
                    if(
                        transport != UP_KEY
                        and transport != DOWN_KEY
                        and transport != LEFT_KEY
                        and transport != RIGHT_KEY
                        and transport != BACK_KEY
                    ):
                        chan.send(transport)
                        command += transport.decode("utf-8")
                
                chan.send("\r\n")
                command = command.rstrip()
                logging.info('Command received ({}): {}'.format(client_ip, command))

                if command == "exit":
                    logging.info("Connection closed (via exit command): " + client_ip + "\n")
                    run = False
                else:
                    handle_cmd(command, chan, client_ip)

        except Exception as err:
            print('Exception: {}: {}'.format(err.__class__, err))
            try:
                transport.close()
            except Exception:
                pass

        chan.close()

    except Exception as err:
        print('Exception occured ')
        try:
            transport.close()
        except Exception:
            pass

#=============================================START-SERVER STEP-1 ===================================================================
def start_server(port, bind) :
    #Init and run the ssh server
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #creating socket for connection
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((bind,port))
        #listens on #bind on the port 2222(default provided)
    except Exception as error:
        print("Bind failed: {}".format(error))
        traceback.print_exc()
        exit(1)

    threads = []
    while True:
        try:
            s.listen(100)
            #can listen upto 100 requests at a time
            print('Listening for Connection on port :  {} '.format(port))
            client,addr = s.accept()
        except Exception as erro:
            print("acceptance failed: {}".format(erro))
            traceback.print_exc()
        new_thread = threading.Thread(target=handle_connection, args=(client, addr))
        new_thread.start()
        threads.append(new_thread)
        for thread in threads :
            thread.join()

#================================== MAIN FOR THE PROGRAM WHEREIN THE HONEYPOT BEGINS ============================================== 
if __name__ == "__main__":
    parser = argparse.ArgumentParser() #CLI BASED ARGPARSING MODULE IMPORTED -> argparse
    parser.add_argument("--port","-p",help="The port to bind the ssh server to (default 22)",default=2222,type=int,action="store")
    #adding args
    parser.add_argument("--bind","-b",help="The address to bind the ssh server to", default="",type=str,action="store")#adding args 
    #here "default" passes the ip for the host machine i.e. my linux based windows subsystem IP
    args=parser.parse_args()
    start_server(args.port,args.bind)

