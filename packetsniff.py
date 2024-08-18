from scapy.all import IP ,sniff ,Raw  ,conf
from customtkinter import *
from tkinter import *
import queue
import threading
import time
import requests
import socket

updategq=queue.Queue()
updateport = queue.Queue()

def psnifed(pac):
    
    if IP in pac:
        psrc=pac[IP].src
        pdest=pac[IP].dst
        pid=pac[IP].id
        pproto=pac[IP].proto
        ppayload=pac[IP].payload
        pversion=pac[IP].version
        pflags = pac[IP].flags
        t=''
        t += f"Source IP : {psrc}\nDestination IP : {pdest}\nPID : {pid}\nProtocol : {pproto}\nPayload : {ppayload}\nIp Version : {pversion}\nFlags : {pflags}\n"



        
        if ppayload.haslayer(Raw): 
            if b"POST" in pac[Raw].load:
                pdata =pac[Raw].load.decode('utf8',errors='ignore')
                t+=f"POST DATA : {pdata} \n\n"

        updategq.put(t)
    pass

def updatefromq():
    while True:
        try:
            packetinf = updategq.get_nowait()
            updategui(packetinf)
        except queue.Empty:
            pass
        time.sleep(0.1)
    pass

def updategui(packett):
    textarea.insert(END, packett + "\n")
    if scrole1.get()[1]==1.0:

        textarea.see(END)
        
    pass


def stsniff():
    iface = conf.iface
    
    sniff(iface=iface, prn=psnifed, store=False)
    pass
def onclicksniffbtn():
    threading.Thread(target=stsniff, daemon=True).start()
    threading.Thread(target=updatefromq, daemon=True).start()

    pass
def onclickclearbtn():
    textarea.delete(1.0, END)
def onclicksavebtn():
    filename = filedialog.asksaveasfilename(defaultextension='.txt',
                                            filetypes = (("text files","*.txt"),("all files","*.*")))
    if filename:
        with open(filename, "w") as f:
            f.write(textarea.get(1.0, END))

    pass

class iplookup:


    def ipmain():
        ip = nentry.get()
        url = f"https://ipinfo.io/{ip}/json"
        try:
            resp = requests.get(url)
            respdata = resp.json()
           
            rescountry = respdata["country"]
            region = respdata["region"]
            city = respdata["city"]
            resloc = respdata["loc"]
            org = respdata["org"]
            postal = respdata["postal"]
            timezone = respdata["timezone"]

            ntextarea.insert(END,f"IP is {ip}\n")
            ntextarea.insert(END,f"Country is {rescountry}\n")
            ntextarea.insert(END,f"Region is {region}\n")
            ntextarea.insert(END,f"City is {city}\n")
            ntextarea.insert(END,f"Location is {resloc}\n")
            ntextarea.insert(END,f"Organization is {org}\n")
            ntextarea.insert(END,f"Postal is {postal}\n")
            ntextarea.insert(END,f"Timezone is {timezone}\n")
            ntextarea.insert(END,f"Google Maps :- https://www.google.com/maps/?q={resloc}\n\n")
            
            

            
            
        except requests.RequestException as e :
            pass



        pass

def onclickipinfobtn():
    global nentry,ntextarea
    newwind = CTk()
    newwind.geometry("720x480")
    newwind.title("IP Info")
    newwind.attributes("-alpha",0.91)
    newwind.iconbitmap('logo.ico')
    newwind.resizable(False, False)
    nframe1 = CTkFrame(newwind)
    nframe1.pack(pady=(10,5), padx=10, fill=BOTH)
    nlable = CTkLabel(nframe1,text='IP information Finder ',font=CTkFont(family="Race Sport"))
    nlable.pack(pady=(10,5), padx=10, fill=BOTH)
    nentry=CTkEntry(nframe1,placeholder_text='Enter IP',font=CTkFont(family='Race Sport'),width=200)
    nentry.pack(pady=(10,10), padx=(200,5),side=LEFT)
    iplookupbtn = CTkButton(nframe1, text='Ip Lookup', font=CTkFont(family="Race Sport"),command=iplookup.ipmain)
    iplookupbtn.pack(side=LEFT,padx=5, pady=10)

    nframe2 = CTkFrame(newwind)
    nframe2.pack(pady=(5,10), padx=10, fill=BOTH,expand=True)
    ntextarea = Text(nframe2,font=("arial"),fg='#39FF14', wrap=WORD, height=20,bg='#212121',borderwidth=0)
    ntextarea.pack(padx=10, pady=10, fill=BOTH, expand=True)
    newwind.mainloop()


    pass

class portscan:
    def portscanner():
        portip = pentry.get()
        scanp = [
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137, 138, 139,
        143, 161, 162, 179, 194, 201, 443, 445, 465, 500, 514, 515, 520, 521, 587, 631, 636,
        993, 995, 1025, 1080, 1194, 1433, 1434, 1512, 1701, 1723, 1812, 1813, 2049, 2082,
        2083, 2086, 2087, 3306, 3389, 5432, 5900, 6000, 6063, 6667, 8000, 8080, 8443, 8888,
        9000, 9090, 9999, 10000, 27017, 27018, 27019, 27020, 50000, 50001, 50002, 50003,
        50004, 50005, 51443, 55000, 55001, 55002, 55003, 55004, 55005, 55006, 55007, 55008,
        55009, 55010, 55011, 55012, 55013, 55014, 55015, 55016, 55017, 55018, 55019, 55020,
        55021]
        
        for port in scanp:
            try:
                pscan = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                pscan.settimeout(0.5)
                pscan.connect((portip,port))
                bot = f'port {port} is open'
                updateport.put(bot)
                

                
                pscan.close()
                

            except:
                pass
        updateport.put(f'\nScan Done :) \n')
def portupdateq():
    timeis = time.asctime()
    ptextarea.insert(END,f'{timeis} \nStarting scan ... \n\n')
    while True:
        try:
            portopen = updateport.get_nowait()
            ptextarea.insert(END, portopen + '\n')
            ptextarea.see(END)
        
        except queue.Empty:
            pass
        
        time.sleep(0.1)
    
    
    


def btnclickport():
    threading.Thread(target=portscan.portscanner,daemon=True).start()
    threading.Thread(target=portupdateq,daemon=True).start()
    pass

def portwind():
    portwind = CTk()
    global pentry,ptextarea
    
    portwind.geometry("720x480")
    portwind.title("IP Info")
    portwind.attributes("-alpha",0.91)
    portwind.iconbitmap('logo.ico')
    portwind.resizable(False, False)
    pframe1 = CTkFrame(portwind)
    pframe1.pack(pady=(10,5), padx=10, fill=BOTH)
    plable = CTkLabel(pframe1,text='Port information ',font=CTkFont(family="Race Sport"))
    plable.pack(pady=(10,5), padx=10, fill=BOTH)
    pentry=CTkEntry(pframe1,placeholder_text='Enter IP',font=CTkFont(family='Race Sport'),width=200)
    pentry.pack(pady=(10,10), padx=(200,5),side=LEFT)
    iplookupbtn = CTkButton(pframe1, text='Port Scan', font=CTkFont(family="Race Sport"),command=btnclickport)
    iplookupbtn.pack(side=LEFT,padx=5, pady=10)

    pframe2 = CTkFrame(portwind)
    pframe2.pack(pady=(5,10), padx=10, fill=BOTH,expand=True)
    ptextarea = Text(pframe2,font=("Race Sport",12),fg='#39FF14', wrap=WORD, height=20,bg='#212121',borderwidth=0)
    ptextarea.pack(padx=10, pady=10, fill=BOTH, expand=True)
    
    portwind.mainloop()

    

set_appearance_mode('dark')
set_default_color_theme('dark-blue')

wind = CTk()

wind.iconbitmap('logo.ico')

wind.geometry('800x480')

wind.title(' Sniffer')
wind.attributes('-alpha', 0.91)




frame1 = CTkFrame(wind)

frame1.pack(pady=(10,5), padx=10, fill=BOTH)
label1 = CTkLabel(frame1, text='Sniff Packet On Your Network ', font=CTkFont(family="Race Sport"))
label1.pack(padx=10, pady=5)
sniffbtn = CTkButton(frame1, text='Sniff',fg_color='#ff0000',text_color='black',hover_color='#ba0606', font=CTkFont(family="Race Sport"), command=onclicksniffbtn)
sniffbtn.pack(side=LEFT,padx=(10), pady=10)
clearbtn = CTkButton(frame1, text='Clear',fg_color='#ff0000',text_color='black',hover_color='#ba0606', font=CTkFont(family="Race Sport"), command=onclickclearbtn)
clearbtn.pack(side=LEFT,padx=5, pady=10)
savebtn = CTkButton(frame1, text='Save',fg_color='#ff0000',text_color='black',hover_color='#ba0606', font=CTkFont(family="Race Sport"), command=onclicksavebtn)
savebtn.pack(side=LEFT,padx=5, pady=10)
ipinfbtn = CTkButton(frame1, text='Ip Info',fg_color='#ff0000',hover_color='#ba0606', font=CTkFont(family="Race Sport"), text_color='black',command=onclickipinfobtn)
ipinfbtn.pack(side=LEFT,padx=5, pady=10)
portbtn = CTkButton(frame1, text='Port Scan',fg_color='#ff0000',hover_color='#ba0606', font=CTkFont(family="Race Sport"), text_color='black',command=portwind)
portbtn.pack(side=LEFT,padx=5, pady=10)
frame2 = CTkFrame(wind)
frame2.pack(pady=(5,10), padx=10, fill=BOTH, expand=True)
textarea = Text(frame2,font=CTkFont(family="Race Sport",size=15),fg='#39FF14', wrap=WORD, height=20,bg='#212121',borderwidth=0)
textarea.pack(padx=10, pady=10, fill=BOTH, expand=True)
scrole1 = CTkScrollbar(textarea)
scrole1.pack(side=RIGHT, fill=Y)
textarea.config(yscrollcommand=scrole1.set)
scrole1.configure(command=textarea.yview)

wind.mainloop()
