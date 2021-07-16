from Crypto.Random import get_random_bytes
from Encryption import AESCrypto
import socket as sc
import bcolors

client_socket = sc.socket(sc.AF_INET, sc.SOCK_STREAM)



RSAKey_N = """2373909629079679939874086414726849121341158767789215600193336339190282947943702661531585360279080363
806934022061879700431112871800064255281732207088706850479904551268635958739401013015290112599250647972771888750197
563065234610830285319015603167020169323997280917154695702486219142929034057890610713687944019262940587271588109762
510340413759228171903781960798978042029882197468555738089485983686637656527105257952357434178301700756247533025290
477161534325397847426684807646312571463406714718630038286700542064566406946597212830060986042623976833001936406263
0659530628312936691220865818936440016501334822244016452038177""".replace('\n', '')
RSAKey_Public = 65537

sessionKey = get_random_bytes(32)
Cryptor = AESCrypto(sessionKey)
#print(sessionKey)
sessionKey = pow(int.from_bytes(sessionKey, 'big'), RSAKey_Public, int(RSAKey_N))
sessionKey = sessionKey.to_bytes(256, 'big')


def SendtoServer(msg: str):
        try:
            client_socket.send(Cryptor.encrypt(msg))
        except Exception as e:
            print(f"Connection Error: [{e}] Exiting...")
            exit(-1)

def ReceivefromServer():
    try:
        msg = client_socket.recv(4096)
        if not msg: raise ConnectionAbortedError
        msg = Cryptor.decrypt(msg)
        return msg
    except Exception as e:
        print(f"Connection Error: [{e}] Exiting...")
        exit(-1)




if __name__ == "__main__":

    print(bcolors.HEADER + '='*55)
    print('|' +' '*20 + "Banking Client" + ' '*20 + '|')
    print('='*55 + bcolors.ENDC)
    
    
    try:
        client_socket.connect(("127.0.0.1",12345))
    except Exception as e:
        print(f"Could not Connect to Server! Error: [{e}]")
        exit(-1)
    client_socket.setblocking(True)
    #Key Exchange
    try:
        client_socket.send(sessionKey)
    except Exception as e:
            print(f"Connection Error: [{e}] Exiting...")
            exit(-1)
    
    while(True):
        cmd = input(">>>")
        splittedCmd = cmd.strip().split(" ")
        # handle signup command
        if(splittedCmd[0] == "signup"):
            if(len(splittedCmd) != 3):
                print("Wrong command format!\n\tUsage: signup [username] [password]")
                continue
            SendtoServer(cmd)
            print("<<< " + ReceivefromServer())
        
        # handle login command
        elif(splittedCmd[0] == "login"):
            if(len(splittedCmd) != 3):
                print("Wrong command format!\n\tUsage: login [username] [password]")
                continue
            SendtoServer(cmd)
            print("<<< " + ReceivefromServer())

            
        # handle create command
        elif(splittedCmd[0] == "create"):
            if(len(splittedCmd) != 5):
                print("Wrong command format!\n\tUsage: create [account_type] [amount] [conf_label] [integrity_label]")
                continue
            SendtoServer(cmd)
            print("<<< " + ReceivefromServer())

        # handle join command
        elif(splittedCmd[0] == "join"):
            if(len(splittedCmd) != 2):
                print("Wrong command format!\n\tUsage: join [account_no]")
                continue
            SendtoServer(cmd)
            print("<<< " + ReceivefromServer())

        # handle accept command
        elif(splittedCmd[0] == "accept"):
            if(len(splittedCmd) != 5):
                print("Wrong command format!\n\tUsage: accept [account_no] [username] [conf_label] [integrity_label]")
                continue
            SendtoServer(cmd)
            print("<<< " + ReceivefromServer())


        # handle show command
        elif(splittedCmd[0] == "show"):
            if(len(splittedCmd) >= 2):
                if(splittedCmd[1] == "myaccounts"):
                    if(len(splittedCmd) != 2):
                        print("Wrong command format!\n\tUsage: show myaccounts")
                        continue
                    SendtoServer(cmd)
                    print("<<< " + ReceivefromServer())
                elif(splittedCmd[1] == "account"):
                    if(len(splittedCmd) != 3):
                        print("Wrong command format!\n\tUsage: show account [account_no]")
                        continue
                    SendtoServer(cmd)
                    print("<<< " + ReceivefromServer())
                else:
                    print("Wrong command format!\n\tUsage: show myaccounts or show account [account_no]")
                    continue
            else:
                print("Wrong command format!\n\tUsage: show myaccounts or show account [account_no]")
                continue


        # handle deposit command
        elif(splittedCmd[0] == "deposit"):
            if(len(splittedCmd) != 4):
                print("Wrong command format!\n\tUsage: deposit [from_account_no] [to_account_no] [amount]")
                continue
            SendtoServer(cmd)
            print("<<< " + ReceivefromServer())


        # handle withdraw command
        elif(splittedCmd[0] == "withdraw"):
            if(len(splittedCmd) != 3):
                print("Wrong command format!\n\tUsage: withdraw [from_account_no] [amount]")
                continue
            print(cmd)
            print(splittedCmd)
            SendtoServer(cmd)
            print("<<< " + ReceivefromServer())

        elif(splittedCmd[0] == "exit"):
            break
        
        else:
            print("<<< Wrong Command!")