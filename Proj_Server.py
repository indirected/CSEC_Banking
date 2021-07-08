#!/bin/python3.9
from enum import Enum, auto
import pickle
import json
import hashlib
import random
import threading


alphabet = "abcdefghijklmnopqrstuvwxyz"
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
digits = "0123456789"
specials = "!@#$%^&*()_+-=/?"


class Confidentiality_lvl_List(Enum):
    TopSecret = 3
    Secret = 2
    Confidential = 1
    Unclassified = 0


class Integrity_lvl_List(Enum):
    VeryTrusted = 3
    Trusted = 2
    SlightlyTrusted = 1
    Untrusted = 0

class Acount_Types(Enum):
    ShortTermSaving = auto()
    LongTermSaving = auto()
    Checking = auto()
    GharzAlHassaneh = auto()

def RandomSubstring(string, length):
    return ''.join(random.sample(string, length))


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

    def AcceptRequest(self, caller, user, conf_lvl, integrity_lvl):
        if user in self.__pendinglist and caller == self.__owner:
            with accounts_lock:
                self.__pendinglist.remove(user)
                self.__userlist[user] = (conf_lvl, integrity_lvl)
                f = open(accounts_filename, 'w')
                json.dump(accounts_dict, f, indent=4)
                f.close()

    def PrintAccountInfo(self, user):
        if user in list(self.__userlist):
            if self.__userlist[user][0].value >= self.__conf_lvl.value and self.__userlist[user][1].value <= self.__integrity_lvl.value:
                #TODO Print Account info
                pass

            



        

        

        

        




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
a = Confidentiality_lvl_List.Secret
b = Confidentiality_lvl_List.Unclassified
print(a.value >= b.value)
print(b)