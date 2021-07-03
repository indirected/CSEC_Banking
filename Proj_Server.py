#!/bin/python3.9
from enum import Enum, auto



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


class user:
    def __init__(self, username, password, conf_lvl, integrity_lvl):
        pass


class account:
    pass