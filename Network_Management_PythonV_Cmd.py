#__batch_scripting__='Mahmoud Khalid'
#__author_to_python__='Hussam Ashraf'

import subprocess as sub
import os
from colorama import Fore, Style




def prnt():

    os.chdir(r'C:\Windows\System32')
    print(
        "-------------------------------------------------------------------------------- \n"
        '--------------------------- Network Management --------------------------------- \n',
        Fore.GREEN + " _   _      _                      _    __  __ \n " 
        "| \ | | ___| |___      _____  _ __| | _|  \/  | __ _ _ __   __ _  __ _  ___ \n "
        "|  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / |\/| |/ _` | '_ \ / _` |/ _` |/ _ \ \n "
        "| |\  |  __/ |_ \ V  V / (_) | |  |   <| |  | | (_| | | | | (_| | (_| |  __/ \n "
        "|_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\_|  |_|\__,_|_| |_|\__,_|\__, |\___| \n "
        "                                                                 |___/        \n \n" + Style.RESET_ALL,
        "------------------------------------------------------------------------------- \n"
    )

    print(
        ' [+] Display IPV4 Address  ==> ' + Fore.RED + '1 \n' + Style.RESET_ALL,
        '[+] Display MAC Address   ==> ' + Fore.RED + '2 \n' + Style.RESET_ALL,
        '[+] Restart Network       ==> ' + Fore.RED + '3 \n' + Style.RESET_ALL,
        '[+] Stop session lease    ==> ' + Fore.RED + '4 \n' + Style.RESET_ALL,
        '[+] Set IPv4 static       ==> ' + Fore.RED + '5 \n' + Style.RESET_ALL,
        '[+] Set IPv4 dynamic      ==> ' + Fore.RED + '6 \n' + Style.RESET_ALL,
        '[+] Display Netstat       ==> ' + Fore.RED + '7 \n' + Style.RESET_ALL,
        '[+] Display DNS Cashe     ==> ' + Fore.RED + '8 \n' + Style.RESET_ALL,
        '[+] Clear DNS Cashe       ==> ' + Fore.RED + '9 \n' + Style.RESET_ALL,
        '[+] Start Hotspot(Laptops)==> ' + Fore.RED + '10 \n' + Style.RESET_ALL,
        '[+] Stop Hotspot (Laptops)==> ' + Fore.RED + '11 \n' + Style.RESET_ALL,
        '[+] Exit the Script       ==> ' + Fore.RED + '12 \n' + Style.RESET_ALL,
        '-----------------------------------'
        )

def usr():

    while True:
        usrInput = int(input('Enter your choice (1 to 12)==> '))
        if usrInput < 13 and usrInput > 0:
            break
    return usrInput

def mainCore():
    cmds = [
        'netsh interface ipv4 show config',
        'ipconfig /all',
        'ipconfig /release',
        'ipconfig /renew',
        'start cmd.exe /k netstat -a',
        'ipconfig /flushdns'
    ]

    while True:
        prnt()
        inputValue = usr()
        if inputValue == 1:
            sub.call(cmds[0], shell=True)
            print('###############################################################')

        elif inputValue == 2:
            sub.call(cmds[1], shell=True)
            print('###############################################################')

        elif inputValue == 3:
            sub.call(cmds[2], shell=True)
            sub.call(cmds[3], shell=True)
            print('###############################################################')

        elif inputValue == 4:
            sub.call(cmds[2], shell=True)
            print('###############################################################')

        elif inputValue == 5:
            sub.call('netsh interface ip show interfaces', shell=True)

            interface = input('Interface Name ==> ')
            ip = input('IPV4 Address ==> ')
            mac = input('IPV4 Subnet ==>')
            ipDefault = input('Default gateway ==> ')
            dnsPrimary = input('Primary DNS ==> ')
            dnsSecondary = input('Secondary DNS ==> ')

            sub.call('netsh interface ipv4 set address name="{}" static {} {} {}'.format(interface, ip, mac, ipDefault), shell=True)
            sub.call('netsh interface ipv4 set dns name="{}" static {}'.format(interface, dnsPrimary), shell=True)
            sub.call('netsh interface ipv4 add dns name="{}" {}'.format(interface, dnsSecondary), shell=True)
            print('###############################################################')

        elif inputValue == 6:
            sub.call('netsh interface ip show interfaces', shell=True)

            interface = input('Interface Name ==> ')

            sub.call('netsh interface ipv4 set address name={} source=dhcp'.format(interface), shell=True)
            sub.call('netsh interface ipv4 set dns "{}" dhcp'.format(interface), shell=True)
            print('###############################################################')


        elif inputValue == 7:
            sub.call(cmds[4], shell=True)
            print('###############################################################')

        elif inputValue == 8:
            sub.call('start cmd.exe /k ipconfig /displaydns', shell=True)
            print('###############################################################')

        elif inputValue == 9:
            sub.call(cmds[6], shell=True)
            print('###############################################################')

        elif inputValue == 10:
            usrName = input('User Name of the network ==> ')
            password = input('Password (Must be more than 8 characters) ==> ')

            sub.call('netsh wlan set hostednetwork  mode=allow  ssid={}  key = {}'.format(usrName, password), shell=True)
            sub.call('netsh wlan start hostednetwork', shell=True)

            print("Now go to Control Panel / Network and Internet / Network and Sharing Center \n"
                  "and open change adapter settings and select the network(Ethernet) you want to share and \n"
                  "click on it’s properties and select the sharing tab and enable the option to share your \n"
                  "internet with Local Hotspot.\n")
            print('###############################################################')

        elif inputValue == 11:
            sub.call('netsh wlan stop hostednetwork', shell=True)
            print('###############################################################')

        elif inputValue == 12:
            break
if __name__ == '__main__':
    mainCore()
