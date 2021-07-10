#!/bin/python3.9
from enum import Enum, auto
import pickle
import json
import hashlib
import random
import threading
import socket as sc
import datetime

server_socket = sc.socket(sc.AF_INET, sc.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 12345))


alphabet = "abcdefghijklmnopqrstuvwxyz"
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
digits = "0123456789"
specials = "!@#$%^&*()_+-=/?"
Password_Requirment = (8, True, False, False, True) #(Length, alphabet, ALPHABET, digit, special)


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

        
        while True:
            command = self.client.recv(1024).decode('ascii').split()

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
                            f.write(f"[{datetime.datetime.now()}]\t User: [{LoggedinUser}] Tried to Withdraw: from Account: [Invalid] from IP address: {self.address[0]}\n")
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