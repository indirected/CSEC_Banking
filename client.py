


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
