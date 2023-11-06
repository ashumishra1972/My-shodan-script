import pyfiglet
from termcolor import colored
import time
import shodan
from tqdm import tqdm

def result(shodan_api_key,query):
    results = shodan_api_key.search(query,limit=1)
    if not results or 'matches' not in results or not results['matches']:
        print(colored(" \n No Results Found \n ",'red'))
    else:
        for resultMatch in results['matches']:
            time.sleep(1)
            print("\n")
            print(colored("IP:", 'yellow') + f" {resultMatch['ip_str']}")
            print(colored("Port:", 'yellow') + f" {resultMatch['port']}")
            print(colored("Organization:", 'yellow') + f" {resultMatch['org']}")
            print(colored("ISP:", 'yellow') + f" {resultMatch['isp']}")
            print('')
            time.sleep(2)


def fetch_internet_cameras(shodan_api_key,bold):
    print(colored(bold + "\n Fetching Webcams From Internet.... \n", 'red'))
    for _ in tqdm(range(2), ascii=True, bar_format="{l_bar}%s{bar}%s{r_bar}" % ('\x1b[92m','\x1b[0m')):
        time.sleep(2)
    result(shodan_api_key,'"Server: yawcam" "Mime-Type: text/html"')
    result(shodan_api_key,'("webcam 7" OR "webcamXP") http.component:"mootools" -401')
    print(colored(bold + "\n Fetching Webcams Sensitive Internal Information",'blue')) 
    result(shodan_api_key,'"Server: IP Webcam Server" "200 OK"')
    result(shodan_api_key,'html:"DVR_H264 ActiveX"')    

def fetch_ics(shodan_api_key,bold):
    print(colored(bold + "\n Fetching Industrial Control System Dashboard From Internet....\n",'red'))
    for _ in tqdm(range(2), ascii=True, bar_format="{l_bar}%s{bar}%s{r_bar}" % ('\x1b[92m','\x1b[0m')):
        time.sleep(2)
    time.sleep(2)
    print(colored(bold + "\n Fetching Gas Station Pump Controllers... ",'blue'))
    result(shodan_api_key,'"in-tank inventory" port:10001')
    print(colored(bold + "\n Fetching IOT License Plate Readers... ",'blue'))
    result(shodan_api_key,'P372 "ANPR enabled"')
    print(colored(bold + "\n Fetching  Internet Connected Satellites... ",'blue'))
    result(shodan_api_key,'"Open Webif"')
    result(shodan_api_key,'("Cobham SATCOM") OR ("Sailor VSAT")')
    result(shodan_api_key,"Sailor VSAT")
    result(shodan_api_key,"Cobham SATCOM")
    print(colored(bold + "\n Fetching Internet Connected Submarine Dashboard ... ",'blue'))
    result(shodan_api_key,"Slocum Fleet Mission Control")
    print(colored(bold + "\n Fetching IOT Refrigeration Units ... ",'blue'))
    result(shodan_api_key,'"Server: CarelDataServer" "200 Document follows"')

def fetch_iot(shodan_api_key,bold):
    print(colored(bold + "\n Fetching IOT Video Conferencing Dashboards ... \n",'red'))
    for _ in tqdm(range(2), ascii=True, bar_format="{l_bar}%s{bar}%s{r_bar}" % ('\x1b[92m','\x1b[0m')):
        time.sleep(2)
    result(shodan_api_key,'"Polycom Command Shell" -failed port:23')
    print(colored(bold + "\n Fetching Internet Connected Media Players  ... ",'blue'))
    result(shodan_api_key,'"Server: Logitech Media Server" "200 OK"')
    print(colored(bold + "\n Fetching IOT Connected Home Devices ... ",'blue'))
    result(shodan_api_key,'"Server: AV_Receiver" "HTTP/1.1 406"')
    print(colored(bold + "\n Fetching IOT 3D Printer Controllers ... ",'blue'))
    result(shodan_api_key,'title:"OctoPrint"+-title:"Login"+http.favicon.hash:1307375944')

def fetch_vulnerable_servers(shodan_api_key,bold):
    print(colored(bold + "\n Fetching Vulnerable Servers... \n",'red'))
    for _ in tqdm(range(2), ascii=True, bar_format="{l_bar}%s{bar}%s{r_bar}" % ('\x1b[92m','\x1b[0m')):
        time.sleep(2)
    result(shodan_api_key,"X-Jenkins+200+OK")
    print(colored(bold + "\n Fetching FTP Servers with Anonymous Login ... ",'blue'))
    result(shodan_api_key,' "220" "230 Login successful." port:21 ')
    print(colored(bold + "\n Fetching Vulnerable Samba Shares [ Network Attached Storage]... ",'blue'))
    result(shodan_api_key,'"Authentication: disabled" port:445')

def fetch_remote_desktop(shodan_api_key,bold):
    print(bold + colored("\n Fetching Unauthenticated Remote Desktop Servers... \n",'red'))
    for _ in tqdm(range(2), ascii=True, bar_format="{l_bar}%s{bar}%s{r_bar}" % ('\x1b[92m','\x1b[0m')):
        time.sleep(2)
    result(shodan_api_key,"authentication disabled RFB 003.008")
    
def fetch_printers(shodan_api_key,bold):
    print(colored(bold + "\n Fetching Online Printers... \n",'red'))
    for _ in tqdm(range(2), ascii=True, bar_format="{l_bar}%s{bar}%s{r_bar}" % ('\x1b[92m','\x1b[0m')):
        time.sleep(2)
    result(shodan_api_key,"Xerox Generic Root")
    result(shodan_api_key,'"Serial Number:" "Built:" "Server: HP HTTP"')
    result(shodan_api_key,'"SERVER: EPSON_Linux UPnP" "200 OK"')
 
def run_all(shodan_api_key,bold):
    fetch_internet_cameras(shodan_api_key,bold)
    fetch_ics(shodan_api_key,bold)
    fetch_iot(shodan_api_key,bold)
    fetch_vulnerable_servers(shodan_api_key,bold)
    fetch_remote_desktop(shodan_api_key,bold)
    fetch_printers(shodan_api_key,bold)
    print(colored(bold + "Thanks for using our tool!", 'green'))

    exit()

def get_Options(shodan_api_key,bold):
    print(colored("\nSelect Choice \n",'green'))
    print("1. Internet Cameras")
    print("2. Scada System / Industrial Control Systems")
    print("3. IOT Ecosystsem / Home Devices")
    print("4. Exposed Server")
    print("5. Remote Desktop")
    print("6. Printers & Copiers")
    print("7. Run All")
    print("8. Exit")

    print("\n ==> Enter your Choice (1-8) ")
    option_input=(int(input()))
    if option_input <=0 or option_input>8 :
        print(colored(bold + "\n Invalid Input !!!!!  ",'red'))
        print(colored(bold + "\n'' RETRY AGAIN Select Options Between  (1-8) '' ",'yellow'))
        time.sleep(1)
        get_Options()
    else:
        if option_input == 1:
            fetch_internet_cameras(shodan_api_key,bold)
            print(colored(bold + " Thanks for using our tool! ", 'green'))
        if option_input == 2:
            fetch_ics(shodan_api_key,bold)
            print(colored(bold + "Thanks for using our tool!", 'green'))
        if option_input == 3:
            fetch_iot(shodan_api_key,bold)
            print(colored(bold + "Thanks for using our tool!", 'green'))
        if option_input == 4:
            fetch_vulnerable_servers(shodan_api_key,bold)
            print(colored(bold + "Thanks for using our tool!", 'green'))
        if option_input == 5:
            fetch_remote_desktop(shodan_api_key,bold)
            print(colored(bold + "Thanks for using our tool!", 'green'))
        if option_input == 6:
            fetch_printers(shodan_api_key,bold)
            print(colored(bold + "Thanks for using our tool!", 'green'))
        if option_input == 7:
            run_all(shodan_api_key,bold)
            print(colored(bold + "Thanks for using our tool!", 'green'))
        if option_input == 8:
            print(colored(bold + "Thanks for using our tool!", 'green'))
            exit()
    

def get_banner(shodan_api_key,bold):
    print("\n\n\n")
    colored_banner= '''


     $$$$$$\  $$\                       $$\                     $$\   $$\            $$\     
$$  __$$\ $$ |                      $$ |                    $$$\  $$ |           $$ |    
$$ /  \__|$$$$$$$\   $$$$$$\   $$$$$$$ | $$$$$$\  $$$$$$$\  $$$$\ $$ | $$$$$$\ $$$$$$\   
\$$$$$$\  $$  __$$\ $$  __$$\ $$  __$$ | \____$$\ $$  __$$\ $$ $$\$$ |$$  __$$\\_$$  _|  
 \____$$\ $$ |  $$ |$$ /  $$ |$$ /  $$ | $$$$$$$ |$$ |  $$ |$$ \$$$$ |$$$$$$$$ | $$ |    
$$\   $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$  __$$ |$$ |  $$ |$$ |\$$$ |$$   ____| $$ |$$\ 
\$$$$$$  |$$ |  $$ |\$$$$$$  |\$$$$$$$ |\$$$$$$$ |$$ |  $$ |$$ | \$$ |\$$$$$$$\  \$$$$  |
 \______/ \__|  \__| \______/  \_______| \_______|\__|  \__|\__|  \__| \_______|  \____/ 
                                                                                         
                                                                                         
                                                                                         
                                                                 Author: Ashutosh Mishras
    '''
    print(colored_banner)
    get_Options(shodan_api_key,bold)

def main():
    shodan_api_key = shodan.Shodan("kPzgGpEx9vqIzPbUbD4HUDlNhj9xvpN2")
    bold = '\x1b[1m'

    get_banner(shodan_api_key,bold)

if __name__ == "__main__":
    main()
