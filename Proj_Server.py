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

        

        

        

        




print(RandomSubstring(alphabet+ALPHABET+digits, 10))
o = user(1,"21")
o = user(2,"22")
listt = {'alo':1}
f = open("file", "w")
#pickle.dump(listt, f)
json.dump(user_passhash_dict, f, indent=4)
f.close()
f = open("file", "r")

#list2 = pickle.load(f)
list2 = json.load(f)
print(list(list2.values()))