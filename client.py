from Crypto.Random import get_random_bytes
from Encryption import AESCrypto

RSAKey_N = """2373909629079679939874086414726849121341158767789215600193336339190282947943702661531585360279080363
806934022061879700431112871800064255281732207088706850479904551268635958739401013015290112599250647972771888750197
563065234610830285319015603167020169323997280917154695702486219142929034057890610713687944019262940587271588109762
510340413759228171903781960798978042029882197468555738089485983686637656527105257952357434178301700756247533025290
477161534325397847426684807646312571463406714718630038286700542064566406946597212830060986042623976833001936406263
0659530628312936691220865818936440016501334822244016452038177""".replace('\n', '')


publicExponent = 65537

sessionKey = get_random_bytes(256)

sessionKey = pow(int.from_bytes(sessionKey, 'big'), publicExponent, int(RSAKey_N))
sessionKey = sessionKey.to_bytes(256, 'big')

cryptoObj = AESCrypto(sessionKey) 




if __name__ == "__main__":
    while(True):
        cmd = input("please enter the proper command or exit to exit from application ...\n")
        splittedCmd = cmd.split(" ")
        # handle signup command
        if(splittedCmd[0] == "signup"):
            if(len(splittedCmd) != 3):
                print("wrong command format:\n\t signup [username] [password]")
                continue
            # TODO
        
        # handle login command
        if(splittedCmd[0] == "login"):
            if(len(splittedCmd) != 3):
                print("wrong command format:\n\t login [username] [password]")
                continue
            # TODO

            
        # handle create command
        if(splittedCmd[0] == "create"):
            if(len(splittedCmd) != 5):
                print("wrong command format:\n\t create [account_type] [amount] [conf_label] [integrity_label]")
                continue
            # TODO

        # handle join command
        if(splittedCmd[0] == "join"):
            if(len(splittedCmd) != 2):
                print("wrong command format:\n\t join [account_no]")
                continue
            # TODO

        # handle accept command
        if(splittedCmd[0] == "accept"):
            if(len(splittedCmd) != 5):
                print("wrong command format:\n\t accept [account_no] [username] [conf_label] [integrity_label]")
                continue
            # TODO


        # handle show command
        if(splittedCmd[0] == "show"):
            if(splittedCmd[1] == "myaccounts"):
                if(len(splittedCmd != 2)):
                    print("wrong command format:\n\t show myaccounts")
                    continue
                # TODO
            elif(splittedCmd[1] == "account"):
                if(len(splittedCmd != 3)):
                    print("wrong command format:\n\t show account [account_no]")
                    continue
                # TODO
            else:
                print("wrong command format:\n\t show myaccounts or show account [account_no]")
                continue    

        # handle deposit command
        if(splittedCmd[0] == "deposit"):
            if(len(splittedCmd) != 4):
                print("wrong command format:\n\t deposit [from_account_no] [to_account_no] [amount]")
                continue
            # TODO


        # handle withdraw command
        if(splittedCmd[0] == "deposit"):
            if(len(splittedCmd) != 4):
                print("wrong command format:\n\t withdraw [from_account_no] [to_account_no] [amount]")
                continue
            # TODO

        if(splittedCmd[0] == "exit"):
            break
