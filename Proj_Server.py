#!/bin/python3.9
from enum import Enum, auto
import pickle
import json
import hashlib
import random
import threading
import socket as sc
import datetime
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

server_socket = sc.socket(sc.AF_INET, sc.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 12345))


alphabet = "abcdefghijklmnopqrstuvwxyz"
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
digits = "0123456789"
specials = "!@#$%^&*()_+-=/?"
Password_Requirment = (8, True, True, True, True) #(Length, alphabet, ALPHABET, digit, special)


RSAKey_N = """2373909629079679939874086414726849121341158767789215600193336339190282947943702661531585360279080363
806934022061879700431112871800064255281732207088706850479904551268635958739401013015290112599250647972771888750197
563065234610830285319015603167020169323997280917154695702486219142929034057890610713687944019262940587271588109762
510340413759228171903781960798978042029882197468555738089485983686637656527105257952357434178301700756247533025290
477161534325397847426684807646312571463406714718630038286700542064566406946597212830060986042623976833001936406263
0659530628312936691220865818936440016501334822244016452038177""".replace('\n', '')

RSAKey_Private = """4922266498247367243381442588114065750630179363640027891271685843608458577537417865870075447584
177344671319472328437867030592308908108879720380695199419776793478942763552503671165962107630398112702298747577276
382262643162407972072683705403517316422338670338747636177298304939992970880974687989305123564623232272494022129501
708209933041259932059310800568165490048260294392671259043763801388653504855690233409943664631128945262023354554568
730269992326457025118806603865336649221357969684233935895723567446153944286754291639620014061032657866570757203982
874827562816594617846731682290764761339121092976642201921913410213""".replace('\n', '')


class Confidentiality_lvl_List(Enum):
    TopSecret = 3
    Secret = 2
    Confidential = 1
    Unclassified = 0

def StringToConfidentialityLvl(s: str):
    if s == 'TopSecret': return Confidentiality_lvl_List.TopSecret
    elif s == 'Secret': return Confidentiality_lvl_List.Secret
    elif s == 'Confidential': return Confidentiality_lvl_List.Confidential
    elif s == 'Unclassified': return Confidentiality_lvl_List.Unclassified
    else: return -1

class Integrity_lvl_List(Enum):
    VeryTrusted = 3
    Trusted = 2
    SlightlyTrusted = 1
    Untrusted = 0

def StringToIntegrityLvl(s: str):
    if s == 'VeryTrusted': return Integrity_lvl_List.VeryTrusted
    elif s == 'Trusted': return Integrity_lvl_List.Trusted
    elif s == 'SlightlyTrusted': return Integrity_lvl_List.SlightlyTrusted
    elif s == 'Untrusted': return Integrity_lvl_List.Untrusted
    else: return -1




class Account_Types(Enum):
    ShortTermSaving = auto()
    LongTermSaving = auto()
    Checking = auto()
    GharzAlHassaneh = auto()

def StringToAccountType(s: str):
    if s == 'ShortTermSaving': return Account_Types.ShortTermSaving
    elif s == 'LongTermSaving': return Account_Types.LongTermSaving
    elif s == 'Checking': return Account_Types.Checking
    elif s == 'GharzAlHassaneh': return Account_Types.GharzAlHassaneh
    else: return -1

def RandomSubstring(string, length):
    return ''.join(random.sample(string, length))


class AESCrypto:
    def __init__(self, key):
        self.__key = key
        self.__blocksize = AES.block_size
    
    def __pad(self, s):
        return s + (self.__blocksize - len(s) % self.__blocksize) * chr(self.__blocksize - len(s) % self.__blocksize)
    
    def __unpad(self, s):
        return s[:-ord(s[-1])]
    
    def encrypt(self, plain: str) -> bytes:
        plain = self.__pad(plain)
        iv = get_random_bytes(self.__blocksize)
        Cryptor = AES.new(self.__key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + Cryptor.encrypt(plain.encode('ascii')))
    
    def decrypt(self, cipher: bytes) -> str:
        cipher = base64.b64decode(cipher)
        iv = cipher[0:self.__blocksize]
        Crypto = AES.new(self.__key, AES.MODE_CBC, iv)
        return self.__unpad(Crypto.decrypt(cipher[self.__blocksize:])).decode('ascii')






#Log file and Lock
LogfileName = "Audit.log"
logfile_lock = threading.Lock()

#UserList and Files
user_passhash_filename = "user_passhash.json"
passhash_lock = threading.Lock()
user_passhash_dict = {}
class user:
    def __init__(self, username, password):
        self.__username = username
        #self.__conf_lvl = conf_lvl
        #self.__integrity_lvl = integrity_lvl
        salt = RandomSubstring(alphabet + ALPHABET + digits, 10)
        with passhash_lock:
            user_passhash_dict[username] = (hashlib.sha256((password + salt).encode('ascii')).hexdigest(), salt)
            f = open(user_passhash_filename, 'w')
            json.dump(user_passhash_dict, f, indent=4)
            f.close()
        #print(user_passhash_dict)



accounts_filename = "accounts.json"
accounts_lock = threading.Lock()
accounts_dict = {}
class account:
    __userlist = {}
    __pendinglist = []
    __accountnumber = 1000000001

    def __init__(self, ownerusername, accounttype, initialamount, conf_lvl, integrity_lvl):
        self.__acounttype = accounttype
        self.__creationdate = datetime.date.today()
        self.__balance = initialamount
        self.__conf_lvl = conf_lvl
        self.__integrity_lvl = integrity_lvl
        self.__owner = ownerusername
        self.__userlist[ownerusername] = (conf_lvl, integrity_lvl)
        
        #set account number
        if accounts_dict:
            self.__accountnumber = list(accounts_dict)[-1] + 1
        with accounts_lock:
            accounts_dict[self.__accountnumber] = self
            f = open(accounts_filename, 'w')
            json.dump(accounts_dict, f, indent=4)
            f.close()
        return self.__accountnumber

    def Withdraw(self, user, amount):
        if user in list(self.__userlist):
            if self.__userlist[user][0].value <= self.__conf_lvl.value and self.__userlist[user][1].value >= self.__integrity_lvl.value:
                if self.__balance >= amount:
                    with accounts_lock:
                        self.__balance -= amount
                        f = open(accounts_filename, 'w')
                        json.dump(accounts_dict, f, indent=4)
                        f.close()
                    return 1 #Success
                else: return 0 #Insufficient balance
        else: return -1 #Access Denied

    
    def Intake(self, amount):
        with accounts_lock:
            self.__balance += amount
            f = open(accounts_filename, 'w')
            json.dump(accounts_dict, f, indent=4)
            f.close()

    def Deposit(self, user, destination, amount):
        if user in list(self.__userlist):
            if self.__userlist[user][0].value <= self.__conf_lvl.value and self.__userlist[user][1].value >= self.__integrity_lvl.value:
                if self.__balance >= amount:
                    with accounts_lock:
                        self.__balance -= amount
                        f = open(accounts_filename, 'w')
                        json.dump(accounts_dict, f, indent=4)
                        f.close()
                    accounts_dict[destination].Intake(amount)
                    return 1 #Success
                else: return 0 #Insufficient Balance
        else: return -1 #Access Denied
    

    def JoinRequest(self, user):
        if user in self.__pendinglist:
            return -1 #User Already in Pending list
        if user in list(self.__userlist):
            return 0 #User Already in Accepted List
        with accounts_lock:
            self.__pendinglist.append(user)
            f = open(accounts_filename, 'w')
            json.dump(accounts_dict, f, indent=4)
            f.close()
        return 1 #Success

    def AcceptRequest(self, caller, user, conf_lvl, integrity_lvl):
        if user in self.__pendinglist and caller == self.__owner:
            with accounts_lock:
                self.__pendinglist.remove(user)
                self.__userlist[user] = (conf_lvl, integrity_lvl)
                f = open(accounts_filename, 'w')
                json.dump(accounts_dict, f, indent=4)
                f.close()
            return 1 #Success

    def isMember(self, user):
        return user in list(self.__userlist)

    def PrintAccountInfo(self, user):
        if user in list(self.__userlist):
            if self.__userlist[user][0].value >= self.__conf_lvl.value and self.__userlist[user][1].value <= self.__integrity_lvl.value:
                #TODO Print Account info
                pass



def PasswordAssesment(passwd: str):
    if len(passwd) < Password_Requirment[0]: return 0 #Low Length

    hasUpper, hasLower, hasDigit, hasSpecial = False, False, False, False
    for char in passwd:
        if char in alphabet: hasLower = True
        elif char in ALPHABET: hasUpper = True
        elif char in digits: hasDigit = True
        elif char in specials: hasSpecial = True
        else: return -2 #Character Not Allowed

    if tuple([a and b for a,b in zip((hasLower, hasUpper, hasDigit, hasSpecial), Password_Requirment[1:])]) == Password_Requirment[1:]: 
        return 1 #Accept Password

    else: return -1 #Requirement not met



class CustomerHandlerThread(threading.Thread):
    def __init__(self, client: sc.socket, address):
        super().__init__()
        self.client = client
        self.address = address
    def run(self):
        self.client.setblocking(True)
        #Audit
        with logfile_lock:
            f = open(LogfileName, 'a')
            f.write(f"[{datetime.datetime.now()}]\t A client connected with IP address: {self.address[0]}\n")
            f.close()

        #Key Exchange
        try:
            SessionKey = self.client.recv(1024)
            if not SessionKey: raise ConnectionAbortedError
            SessionKey = pow(int.from_bytes(SessionKey, 'big'), int(RSAKey_Private), int(RSAKey_N))
            SessionKey = SessionKey.to_bytes(32, 'big')
        except Exception as e:
            #Audit
            with logfile_lock:
                f = open(LogfileName, 'a')
                f.write(f"[{datetime.datetime.now()}]\t Client Unexpectedly Discconected During Key Exchange with Error: [{e}] from IP address: {self.address[0]}\n")
                f.close()
                print(f"Connection Error: [{e}] in Thread: [{self.name}] - Ending Thread...")
                return
        
        #Create Cryptography Object
        Cryptor = AESCrypto(SessionKey)

        while True:

            try:
                command = self.client.recv(1024).decode('ascii').split()
                if not command: raise ConnectionAbortedError
            except Exception as e:
                #Audit
                with logfile_lock:
                    f = open(LogfileName, 'a')
                    f.write(f"[{datetime.datetime.now()}]\t Client Unexpectedly Discconected with Error: [{e}] from IP address: {self.address[0]}\n")
                    f.close()
                    print(f"Connection Error: [{e}] in Thread: [{self.name}] - Ending Thread...")
                    return

            #Audit
            with logfile_lock:
                f = open(LogfileName, 'a')
                f.write(f"[{datetime.datetime.now()}]\t Recieved Command: [{' '.join(command)}] from IP address: {self.address[0]}\n")
                f.close()


            LoggedinUser = ''
            if command[0] == "signup":
                if LoggedinUser != '':

                    #Audit
                    with logfile_lock:
                        f = open(LogfileName, 'a')
                        f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to signup while Logged in from IP address: {self.address[0]}\n")
                        f.close()

                    #TODO You are Already Logged in
                    continue
                if len(command) == 3:
                    username = command[1]
                    password = command[2]
                    if user in list(user_passhash_dict):
                        #Audit
                        with logfile_lock:
                            f = open(LogfileName, 'a')
                            f.write(f"[{datetime.datetime.now()}]\t A client Tried to Create a Repetitive User: [{username}] with IP address: {self.address[0]}\n")
                            f.close()
                        #TODO User Already Exists
                        
                    #Test username to be in the Allowed character list
                    elif ''.join([char for char in username if char in alphabet+ALPHABET+digits]) == username:
                        #Test Password
                        passAssesst = PasswordAssesment(password)
                        if passAssesst == 1:
                            #Create User
                            user(username, password)

                            #Audit
                            with logfile_lock:
                                f = open(LogfileName, 'a')
                                f.write(f"[{datetime.datetime.now()}]\t A client Created a New User: [{username}] with IP address: {self.address[0]}\n")
                                f.close()
                            #TODO User Created
                        elif passAssesst == 0:
                            #TODO Password is short
                            pass
                        elif passAssesst == -1:
                            #TODO Reqs not met - Print Reqs
                            pass
                        elif passAssesst == -2:
                            #TODO Not Allowed characters in passwd
                            pass
                    else:
                        #Audit
                        with logfile_lock:
                            f = open(LogfileName, 'a')
                            f.write(f"[{datetime.datetime.now()}]\t A client Tried to Create a Invalid Username: [{username}] with IP address: {self.address[0]}\n")
                            f.close()
                        #TODO Invalid Username
                continue


            elif command[0] == "login":
                if LoggedinUser != '':
                    #Audit
                    with logfile_lock:
                        f = open(LogfileName, 'a')
                        f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to loggin while Logged in from IP address: {self.address[0]}\n")
                        f.close()
                    #TODO You Are Already Logged in
                    continue
                if len(command) == 3:
                    username = command[1]
                    password = command[2]
                    if username in list(user_passhash_dict):
                        savedHash, savedSalt = user_passhash_dict[username]
                        newHash = hashlib.sha256((password + savedSalt).encode('ascii')).hexdigest()
                        if newHash == savedHash:
                            LoggedinUser = username
                            #Audit
                            with logfile_lock:
                                f = open(LogfileName, 'a')
                                f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Logged in from IP address: {self.address[0]}\n")
                                f.close()
                            
                            #TODO Logged in
                        else:
                            #Audit
                            with logfile_lock:
                                f = open(LogfileName, 'a')
                                f.write(f"[{datetime.datetime.now()}]\t User: [{username}] Tried to loggin with Wrong Password: [{password}] from IP address: {self.address[0]}\n")
                                f.close()
                            #TODO Wrong Passwd

                    else:
                        #Audit
                        with logfile_lock:
                            f = open(LogfileName, 'a')
                            f.write(f"[{datetime.datetime.now()}]\t A Client Tried to login with a Non-Existing User: [{username}] with Password: [{password}] from IP address: {self.address[0]}\n")
                            f.close()
                        #TODO user not exists
                        pass
                continue


            elif command[0] == "create":
                if LoggedinUser == '':
                    #Audit
                    with logfile_lock:
                        f = open(LogfileName, 'a')
                        f.write(f"[{datetime.datetime.now()}]\t A client Tried to Create a new Account without Logging in from IP address: {self.address[0]}\n")
                        f.close()
                    #TODO Login First
                    continue
                if len(command) == 5:
                    EnumedAccountType = StringToAccountType(command[1])
                    if EnumedAccountType == -1:
                        #TODO Wrong Account Type
                        continue
                    
                    if command[2].isdigit(): 
                        amount = int(command[2])
                    else:
                        #TODO Wrong Amount
                        continue

                    EnumedConf_lvl = StringToConfidentialityLvl(command[3])
                    if EnumedConf_lvl == -1:
                        #TODO Wrong Conf Label
                        continue
                    
                    EnumedIntegrity_lvl = StringToIntegrityLvl(command[4])
                    if EnumedIntegrity_lvl == -1:
                        #TODO Wrong Integrity Label
                        continue

                    acountnum = account(LoggedinUser, EnumedAccountType, amount, EnumedConf_lvl, EnumedIntegrity_lvl)
                    #Audit
                    with logfile_lock:
                        f = open(LogfileName, 'a')
                        f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Created an Account: [{acountnum}] from IP address: {self.address[0]}\n")
                        f.close()
                    #TODO Print Accountnum
                continue


            elif command[0] == "join":
                if LoggedinUser == '':
                    #Audit
                    with logfile_lock:
                        f = open(LogfileName, 'a')
                        f.write(f"[{datetime.datetime.now()}]\t A client Tried to Join an Account without Logging in from IP address: {self.address[0]}\n")
                        f.close()
                    #TODO Login First
                    continue
                if len(command) == 2:
                    if command[1].isdigit():
                        accountnum = int(command[1])
                        if accountnum in list(accounts_dict):
                            joinresult = accounts_dict[accountnum].JoinRequest(LoggedinUser)
                            if joinresult == -1:
                                #Audit
                                with logfile_lock:
                                    f = open(LogfileName, 'a')
                                    f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Requested to Join Account: [{accountnum}] While Already in Pending from IP address: {self.address[0]}\n")
                                    f.close()
                                #TODO Already in Pending
                                continue
                            elif joinresult == 0:
                                #Audit
                                with logfile_lock:
                                    f = open(LogfileName, 'a')
                                    f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Requested to Join Account: [{accountnum}] While Already a Member from IP address: {self.address[0]}\n")
                                    f.close()
                                #TODO Already a member
                                continue
                            elif joinresult == 1:
                                #Audit
                                with logfile_lock:
                                    f = open(LogfileName, 'a')
                                    f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Successfuly Requested to Join Account: [{accountnum}] from IP address: {self.address[0]}\n")
                                    f.close()
                                #TODO Success
                                
                        else:
                            #Audit
                            with logfile_lock:
                                f = open(LogfileName, 'a')
                                f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Requested to Join Account: [{accountnum}] Which Doesn't Exist from IP address: {self.address[0]}\n")
                                f.close()
                            #TODO Account doesnt Exist
                    else:
                        #Audit
                        with logfile_lock:
                            f = open(LogfileName, 'a')
                            f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Requested to Join A non Valid Account number from IP address: {self.address[0]}\n")
                            f.close()
                        #TODO Enter a valid Account num
                continue

                
            elif command[0] == "accept":
                if LoggedinUser == '':
                    #Audit
                    with logfile_lock:
                        f = open(LogfileName, 'a')
                        f.write(f"[{datetime.datetime.now()}]\t A client Tried to Accept a Join without Logging in from IP address: {self.address[0]}\n")
                        f.close()
                    #TODO Login First
                    continue
                if len(command) == 5:
                    if command[1].isdigit():
                        accountnum = int(command[1])
                        if accountnum in list(accounts_dict):
                            username = command[2]
                            EnumedConf_lvl = StringToConfidentialityLvl(command[3])
                            if EnumedConf_lvl == -1:
                                #TODO Wrong Conf Label
                                continue
                            
                            EnumedIntegrity_lvl = StringToIntegrityLvl(command[4])
                            if EnumedIntegrity_lvl == -1:
                                #TODO Wrong Integrity Label
                                continue
                            
                            acceptresult = accounts_dict[accountnum].AcceptRequest(LoggedinUser, username, EnumedConf_lvl, EnumedIntegrity_lvl)
                            if acceptresult == 1:
                                #Audit
                                with logfile_lock:
                                    f = open(LogfileName, 'a')
                                    f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Successfuly Accepted User: [{username}] Request to Join Account: [{accountnum}] from IP address: {self.address[0]}\n")
                                    f.close()
                                #TODO User Accepted
                                
                            else:
                                #Audit
                                with logfile_lock:
                                    f = open(LogfileName, 'a')
                                    f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Accepted User: [{username}] Request to Join Account: [{accountnum}] While he is not in Pending from IP address: {self.address[0]}\n")
                                    f.close()
                                #TODO User not in pending list
                                
                        else:
                            #Audit
                            with logfile_lock:
                                f = open(LogfileName, 'a')
                                f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Accept a Request on Account: [{accountnum}] Which Doesn't Exist from IP address: {self.address[0]}\n")
                                f.close()
                            #TODO Account doesnt Exist
                            
                    else:
                        #Audit
                        with logfile_lock:
                            f = open(LogfileName, 'a')
                            f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Requested to Accept a Request on A non Valid Account number from IP address: {self.address[0]}\n")
                            f.close()
                        #TODO wrong Account number
                        
                continue


            elif command[0] == "show":
                if LoggedinUser == '':
                    #Audit
                    with logfile_lock:
                        f = open(LogfileName, 'a')
                        f.write(f"[{datetime.datetime.now()}]\t A client Tried to Request a Show without Logging in from IP address: {self.address[0]}\n")
                        f.close()
                    #TODO Login First
                    continue
                if command[1] == "myaccounts":
                    if len(command) == 2:
                        result = [acc for acc in list(accounts_dict) if accounts_dict[acc].isMember(LoggedinUser)]
                        #Audit
                        with logfile_lock:
                            f = open(LogfileName, 'a')
                            f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Successfuly Requested his Accounts List from IP address: {self.address[0]}\n")
                            f.close()
                        #TODO send the list
                    continue
                elif command[1] == "account":
                    if len(command) == 3:
                        if command[2].isdigit():
                            accountnum = int(command[2])
                            if accountnum in list(accounts_dict):
                                #TODO
                                pass
                            else:
                                #Audit
                                with logfile_lock:
                                    f = open(LogfileName, 'a')
                                    f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Requested to Show Account: [{accountnum}] Which Doesn't Exist from IP address: {self.address[0]}\n")
                                    f.close()
                                #TODO Account not exists
                        else:
                            #Audit
                            with logfile_lock:
                                f = open(LogfileName, 'a')
                                f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Requested to Show A non Valid Account number from IP address: {self.address[0]}\n")
                                f.close()
                            #TODO Enter a valid Account num
                continue


            elif command[0] == "deposit":
                if LoggedinUser == '':
                    #Audit
                    with logfile_lock:
                        f = open(LogfileName, 'a')
                        f.write(f"[{datetime.datetime.now()}]\t A client Tried to Deposit to an Account without Logging in from IP address: {self.address[0]}\n")
                        f.close()
                    #TODO Login First
                    continue
                if len(command) == 4:
                    if command[1].isdigit():
                        source = int(command[1])
                        if source in list(accounts_dict):
                            if command[2].isdigit:
                                destination = int(command[2])
                                if destination in list(accounts_dict):
                                    if command[3].isdigit():
                                        amount = int(command[3])
                                        depositresult = accounts_dict[source].Deposit(LoggedinUser, destination, amount)
                                        if depositresult == 1:
                                            #Audit
                                            with logfile_lock:
                                                f = open(LogfileName, 'a')
                                                f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Successfuly Deposited: [{amount}T] from Account: [{source}] to Account: [{destination}] from IP address: {self.address[0]}\n")
                                                f.close()
                                            #TODO Deposit Success
                                            
                                        elif depositresult == 0:
                                            #Audit
                                            with logfile_lock:
                                                f = open(LogfileName, 'a')
                                                f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Deposit: [{amount}T] from Account: [{source}] to Account: [{destination}] With Insufficient Source Balance from IP address: {self.address[0]}\n")
                                                f.close()
                                            #TODO Low Balance
                                        elif depositresult == -1:
                                            #Audit
                                            with logfile_lock:
                                                f = open(LogfileName, 'a')
                                                f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Deposit: [{amount}T] from Account: [{source}] to Account: [{destination}] With No Write Access to Source from IP address: {self.address[0]}\n")
                                                f.close()
                                            #TODO Access Denied
                                    else:
                                        #Audit
                                        with logfile_lock:
                                            f = open(LogfileName, 'a')
                                            f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Deposit: [InValid] Amount from Account: [{source}] to Account: [{destination}] from IP address: {self.address[0]}\n")
                                            f.close()
                                        #TODO Invalid Amount
                                else:
                                    #Audit
                                    with logfile_lock:
                                        f = open(LogfileName, 'a')
                                        f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Deposit from Account: [{source}] to Account: [{destination}] Which doesn't Exist from IP address: {self.address[0]}\n")
                                        f.close()
                                    #TODO Destination not exists
                            else:
                                #Audit
                                with logfile_lock:
                                    f = open(LogfileName, 'a')
                                    f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Deposit from Account: [{source}] to an [Invalid] Account from IP address: {self.address[0]}\n")
                                    f.close()
                                #TODO Invalid Destination
                        else:
                            #Audit
                            with logfile_lock:
                                f = open(LogfileName, 'a')
                                f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Deposit from Account: [{source}] Which doesn't Exist from IP address: {self.address[0]}\n")
                                f.close()
                            #TODO Source not exists
                    else:
                        #Audit
                        with logfile_lock:
                            f = open(LogfileName, 'a')
                            f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Deposit from an [Invalid] Account from IP address: {self.address[0]}\n")
                            f.close()
                        #TODO Invalid Source
                continue

            elif command[0] == "withdraw":
                if LoggedinUser == '':
                    #Audit
                    with logfile_lock:
                        f = open(LogfileName, 'a')
                        f.write(f"[{datetime.datetime.now()}]\t A client Tried to Withdraw from an Account without Logging in from IP address: {self.address[0]}\n")
                        f.close()
                    #TODO Login First
                    continue
                if len(command) == 3:
                    if command[1].isdigit():
                        source = int(command[1])
                        if source in list(accounts_dict):
                            if command[2].isdigit():
                                amount = int(command[2])
                                withdrawresult = accounts_dict[source].Withdraw(LoggedinUser, amount)
                                if withdrawresult == 1:
                                    #Audit
                                    with logfile_lock:
                                        f = open(LogfileName, 'a')
                                        f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Successfuly Withdrawed: [{amount}T] from Account: [{source}] from IP address: {self.address[0]}\n")
                                        f.close()
                                    #TODO Withdraw Success
                                elif withdrawresult == 0:
                                    #Audit
                                    with logfile_lock:
                                        f = open(LogfileName, 'a')
                                        f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Withdraw: [{amount}T] from Account: [{source}] With Insufficent Balance from IP address: {self.address[0]}\n")
                                        f.close()
                                    #TODO Low Balance
                                elif withdrawresult == -1:
                                    #Audit
                                    with logfile_lock:
                                        f = open(LogfileName, 'a')
                                        f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Withdraw: [{amount}T] from Account: [{source}] With No Write Access from IP address: {self.address[0]}\n")
                                        f.close()
                                    #TODO Access Denied
                            else:
                                #Audit
                                with logfile_lock:
                                    f = open(LogfileName, 'a')
                                    f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Withdraw: [InValid] Amount from Account: [{source}] from IP address: {self.address[0]}\n")
                                    f.close()
                                #TODO Invalid Amount
                        else:
                            #Audit
                            with logfile_lock:
                                f = open(LogfileName, 'a')
                                f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Withdraw: from Account: [{source}] Which doesn't Exist from IP address: {self.address[0]}\n")
                                f.close()
                            #TODO Source not exists
                            
                    else:
                        #Audit
                        with logfile_lock:
                            f = open(LogfileName, 'a')
                            f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Withdraw: from Account: [Invalid] Which doesn't Exist from IP address: {self.address[0]}\n")
                            f.close()
                        #TODO Invalid Source
                continue


            elif command[0] == "exit":
                pass
            
            else:
                pass
            

        print(self.name)
        




if __name__ == "__main__":
    # thread_list = []
    # server_socket.listen(10)
    # while True:
    #     cli, addr = server_socket.accept()
    #     newthread = CustomerHandlerThread(cli, addr)
    #     newthread.start()
    #     thread_list.append[newthread]
    # dict = {"alo":"balo"}
    # print('ball'in list(dict)
    #username = 'alobaloA25+amFDE85_'
    #print("".join([char for char in username if char in alphabet+ALPHABET+digits]))
    #print((True, True, False, True) & Password_Requirment[1:] == Password_Requirment[1:])
    #print(tuple([a and b for a,b in zip((True, True, False, True), Password_Requirment[1:])])== Password_Requirment[1:])
    print(datetime.datetime.now())
    # s = """26:fd:ea:a1:f7:18:10:7b:0d:11:37:c3:55:a7:f8:
    # 5b:ac:ea:7e:93:85:b9:dc:0f:a5:b7:8c:53:b1:d2:
    # 86:1f:2b:f3:82:48:ad:67:f2:cf:71:d3:52:ea:1e:
    # 11:63:0c:86:22:29:37:a7:c2:18:50:76:a4:18:65:
    # 62:08:de:cb:47:49:0f:5e:24:d8:72:fd:16:ed:1c:
    # 31:c2:c5:74:a3:ed:25:e7:86:15:a9:0a:24:45:65:
    # 38:48:13:25:f7:4f:2c:b6:1a:54:02:d2:f9:ee:8e:
    # 40:5a:e7:26:27:cf:8d:fa:16:09:ca:4b:c6:83:2f:
    # 9f:e4:69:5b:1c:c7:5b:33:6a:d6:71:1a:fb:be:ca:
    # ec:c6:f0:27:86:a3:05:ad:2d:37:68:b3:a3:48:b6:
    # 7d:67:6f:4a:bd:b7:f2:12:02:20:3e:25:ff:16:79:
    # 72:c4:f2:04:c8:83:fe:7f:1c:40:01:97:c5:63:b7:
    # b8:67:40:c4:69:4f:0c:07:44:63:99:90:5a:b5:32:
    # fd:9e:67:b6:2c:5d:ca:f4:9e:ff:8b:2c:95:86:74:
    # db:4b:f7:4a:8f:1a:91:08:59:c5:24:0b:5f:51:34:
    # 54:30:94:c4:52:69:24:5d:06:d4:dc:d5:44:bf:e4:
    # b9:01:d2:8f:15:f0:f2:8a:a1:ce:98:91:95:78:d2:
    # a5"""

    # s = s.replace('\n', '').replace(':', '').replace(' ', '')
    # print(int(RSAKey_N.replace('\n', '')))
    b = 'adkwdkw'.encode()
    intb = int.from_bytes(b, 'big')
    print(b)
    print(intb)
    a = pow(264545615184, int(RSAKey_Private), int(RSAKey_N))
    bytea = a.to_bytes(256, 'big')
    print(a)
    print(bytea)
    print(int.from_bytes(bytea, 'big'))
        

        

        




# print(RandomSubstring(alphabet+ALPHABET+digits, 10))
# o = user(1,"21")
# o = user(2,"22")
# listt = {'alo':1}
# f = open("file", "w")
# #pickle.dump(listt, f)
# json.dump(user_passhash_dict, f, indent=4)
# f.close()
# f = open("file", "r")

# #list2 = pickle.load(f)
# list2 = json.load(f)
# print(list(list2.values()))
#a = Confidentiality_lvl_List.Secret
#b = Confidentiality_lvl_List.Unclassified
#print(a.value >= b.value)
#print(b)