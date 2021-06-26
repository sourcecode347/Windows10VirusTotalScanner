# Source Code 347 Windows 10 Shield ( Nikolaos Bazigos )
#https://patorjk.com/software/taag/#p=display&h=3&v=3&f=Small&t=Source%20Code%20347%20%0AVirusTotal%20Scanner

MITLicense = '''
MIT License

Copyright (c) 2021 SourceCode347(Nikolaos Bazigos)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

https://github.com/sourcecode347/Windows10VirusTotalScanner
Official Website: https://sourcecode347.com
Youtube Channel: https://youtube.com/sourcecode347
'''

license = '''
  ___                        ___        _       _____ _ ____              
 / __|___ _  _ _ _ __ ___   / __|___ __| |___  |__ | | |__  |             
 \__ / _ | || | '_/ _/ -_) | (__/ _ / _` / -_)  |_ |_  _|/ /              
 ____\___/\_,_|_| \__\_____ \___\___\__,_\_____|___/ |_|/_/               
 \ \ / (_)_ _ _  _ __|_   ____| |_ __ _| | / __|__ __ _ _ _  _ _  ___ _ _ 
  \ V /| | '_| || (_-< | |/ _ |  _/ _` | | \__ / _/ _` | ' \| ' \/ -_| '_|
   \_/ |_|_|  \_,_/__/ |_|\___/\__\__,_|_| |___\__\__,_|_||_|_||_\___|_|  
                                                                          
'''

import os,subprocess,sys,random,time
import hashlib , requests

VirusTotalApiKey = "ENTER HERE YOUR VIRUSTOTAL API KEY"

RunningApps = []
ScannedFiles = []
Hashes = []
scannedHashes = []
TotalScans = 0
Detections = []
Permalinks = []

def set():
    try:
        os.system("del permalinks.txt")
    except:
        pass
    try:
        with open('permalinks.txt', 'w') as file:
            file.write("")
    except:
        pass
    '''try:
        os.system("del detections.txt")
    except:
        pass'''
    try:
        if os.path.isfile("detections.txt")==False:
            with open('detections.txt', 'w') as file:
                file.write("")
    except:
        pass

def getsha256(filename):
    with open(filename,"rb") as f:
        bytes = f.read()
        readable_hash = hashlib.sha256(bytes).hexdigest();
        return readable_hash

def vtscan(file):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': VirusTotalApiKey}
    files = {'file': (file, open(file, 'rb'))}
    response = requests.post(url, files=files, params=params)
    time.sleep(2)
    resp = response.json()
    try:
        return (resp['permalink'])
    except:
        pass
        return False

def vtreport(sfile,type):
    if type=="file":
        sfile = getsha256(sfile)
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VirusTotalApiKey}
    files = {'resource': sfile}
    response = requests.post(url, params=params , files=files)
    time.sleep(2)
    resp = response.json()
    #print(resp['permalink'])
    #print(response.json())
    total=0
    positves=0
    permalink = " Null "
    prints = ["total","positives","sha256","permalink","response_code","scan_date"] 
    for x in resp:
        if x == "scans":
            #print(x)
            for r1 in resp[x]:
                result = ""
                for r2 in resp[x][r1]:
                    result +=" "+str(resp[x][r1][r2])
                #print(r1+" : "+result)
        else:
            if x in prints:
                print(x+" : "+str(resp[x]))
            if x == "total":
                total = int(resp[x])
            if x == "positives":
                positives = int(resp[x])
            if x == "permalink":
                permalink = str(resp[x])
            if x == "response_code":
                response_code = int(resp[x])
    if response_code == 0:
        return False
    elif response_code == 1:
        return [positives,total,permalink]
    else:
        return None

def randomFileFromFolder(folder):
    return random.choice([x for x in os.listdir(folder) if os.path.isfile(os.path.join(folder, x))])

def executeCMD(cmd):
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout_value = proc.stdout.read() + proc.stderr.read()
        output3 = stdout_value.decode("utf-8","ignore")
        #print(output3)
        return(output3)
    except:
        pass
        return False

def analysis(sfile ,type):
    scan = vtreport(sfile,type)
    if scan == None:
        print(sfile)
        print("Error File Not Scanned (!)")
        print("We Not Get response_code (!)")
    elif scan == False:
        print(sfile)
        print("The Hash of File Not Exists in VT Database (!)")
        vts = vtscan(sfile)
        if vts == False:
            print("Error File Not Submited For VT Analysis(!)")
        else:
            if vts not in Permalinks:
                with open("permalinks.txt","a") as plf:
                    plf.write(vts+"\n")
                Permalinks.append(vts)
            print("File Submited For Analysis and Permalink Saved.")
            return vts
    else:
        if scan[0]>0:
            print((" "*80))
            print (" Danger (!)")
            print (" Virus Detected (!)")
            print (" Please Check this File : "+sfile)
            print (" Permalink : "+str(scan[2]))
            print (" "+str(scan[0])+" / "+str(scan[1])+" Detection Rate")
            if sfile not in Detections:
                with open("detections.txt","a") as dtc:
                    dtc.write(sfile+"\n"+str(scan[2])+"\n")
                Detections.append(sfile)
            print((" "*80))
        if scan[0]==0:
            print((" "*80))
            print (" This File is undetected : "+sfile)
            print (" Detection Rate : "+str(scan[0])+" / "+str(scan[1]))
            print((" "*80))
            return sfile

#print(analysis("C:\Windows\System32\MoUsoCoreWorker.exe","file"))
def RandomFile():
    des = random.randint(0,3)
    if des == 0:
        directory = "C:\\"
        directories = [directory]
    if des == 1:
        directory = "C:\\Windows\\System32\\"
        directories = [directory]
    if des == 2:
        directory = "C:\\Users\\"+os.environ.get('USERNAME')+"\\"
        directories = [directory]
    else:
        directory = "C:\\Users\\"+os.environ.get('USERNAME')+"\\Desktop\\"
        directories = [directory]
    for root, subdirectories, files in os.walk(directory):
        for subdirectory in subdirectories:
            dir = os.path.join(root, subdirectory)
            directories.append(dir)
    dirfiles = []
    Rdirectory = directories[random.randint(0,len(directories)-1)]
    for root, subdirectories, files in os.walk(Rdirectory):
        for subdirectory in subdirectories:
            dir = os.path.join(root, subdirectory)
        for file in files:
            dirfiles.append(os.path.join(root, file))
    if len(dirfiles)>0:
        rf = dirfiles[random.randint(0,len(dirfiles)-1)]
        if os.path.isfile(rf):
            return rf
set()
os.system("cls")
print(license)
#print(analysis("3d3ed27eea5c3557e8b019db92482944dc069cadbfa39a721ecdbf32140796df" , "hash"))

while True:
    pro = executeCMD('wmic process get ExecutablePath | findstr "C:\\" ')
    pro = pro.split("\n")
    for p in pro:
        try:
            pos=p.find(" ")
            exe = p[0:pos]
            path = executeCMD("where "+exe)
            if "C:\\" in path:
                ap = path.replace("\n","").replace("\r","")
                if ap not in RunningApps:
                    RunningApps.append(ap)
        except:
            pass
    pro = executeCMD("tasklist")
    pro = pro.split("\n")
    for p in pro:
        try:
            pos=p.find(" ")
            exe = p[0:pos]
            path = executeCMD("where "+exe)
            if "C:\\" in path:
                ap = path.replace("\n","").replace("\r","")
                if ap not in RunningApps:
                    RunningApps.append(ap)
        except:
            pass
    for ap in RunningApps:
        ap = ap.replace("\r","").replace("\n","")
        if os.path.isfile(ap) and ap not in ScannedFiles:
            os.system("cls")
            print(license)
            with open("detections.txt","r") as df:
                dfcount = 0
                for dl in df:
                    if dl != "\n":
                        dfcount+=1
            with open("permalinks.txt","r") as pf:
                pfcount = 0
                for pl in pf:
                    if pl != "\n":
                        pfcount+=1
            TotalScans+=1
            print(("#"*80))
            print("### Detections : "+str(int(dfcount/2))+" | Permalinks : "+str(pfcount)+" | TotalScans : "+str(TotalScans)+" | UnresponsedHashes : "+str(len(Hashes)))
            print(("#"*80))
            #print(ap)
            print("File : "+str(ap))
            sc347 = ""
            try:
                sc347 = analysis(ap , "file")
            except:
                pass
            vtag = "https://www.virustotal.com/gui/file/"
            if sc347 != None and sc347!="":
                if vtag in sc347:
                    sc347 = sc347.replace(vtag,"")
                    sc347 = sc347[:sc347.find("/detection")]
                    if sc347 not in Hashes:
                        Hashes.append(sc347)
                ScannedFiles.append(ap)
            time.sleep(15)
        else:
            hashrnum = random.randint(0,1)
            if hashrnum == 0 and len(Hashes)>0:
                sha256hash = str(Hashes[random.randint(0,len(Hashes)-1)]).replace("\n","").replace("\r","")
                os.system("cls")
                print(license)
                print("sha256 : "+sha256hash)
                print("Checking Back The Hash of Submited File")
                sc347 = ""
                try:
                    sc347 = analysis(sha256hash , "hash")
                except:
                    pass
                if sc347 !="":
                    Hashes.remove(sha256hash)
                time.sleep(15)
            else:        
                rfile = RandomFile()
                rfile = str(rfile).replace("\n","").replace("\r","")
                if os.path.isfile(rfile) and rfile not in ScannedFiles:
                    os.system("cls")
                    print(license)
                    with open("detections.txt","r") as df:
                        dfcount = 0
                        for dl in df:
                            if dl != "\n":
                                dfcount+=1
                    with open("permalinks.txt","r") as pf:
                        pfcount = 0
                        for pl in pf:
                            if pl != "\n":
                                pfcount+=1
                    TotalScans+=1
                    print(("#"*80))
                    print("### Detections : "+str(int(dfcount/2))+" | Permalinks : "+str(pfcount)+" | TotalScans : "+str(TotalScans)+" | UnresponsedHashes : "+str(len(Hashes)))
                    print(("#"*80))
                    print("File : "+str(rfile))
                    sc347 = ""
                    try:
                        sc347 = analysis(rfile , "file")
                    except:
                        pass
                    vtag = "https://www.virustotal.com/gui/file/"
                    if sc347 != None and sc347 !="":
                        if vtag in sc347:
                            sc347 = sc347.replace(vtag,"")
                            sc347 = sc347[:sc347.find("/detection")]
                            if sc347 not in Hashes:
                                Hashes.append(sc347)
                        ScannedFiles.append(rfile)
                    time.sleep(15)