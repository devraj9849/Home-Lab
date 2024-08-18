# Home-Lab

Detection Lab
 
Figure 1 Network Diagram
<h1>Part1: Installing pfsense firewall</h1>
For this lab first installing pfsense in the VMware workstation pro. Go to the link

    https://archive.org/details/pfSense-CE-2.6.0-RELEASE-amd64

![image](https://github.com/user-attachments/assets/4f5f7b48-1d62-4760-8f02-7dddd9887586)

 
Go to Edit>Virtual Network Editor >Change Settings>Add Network.
In VMnet0 type bridged add Microsoft Wifi Direct Virtual Adapter in case of Automatic.After this click Apply.

![image](https://github.com/user-attachments/assets/f765211a-1190-410b-b0e5-edfcaf0b0564)

 
In our network adapter in case of bridged adapter place it under VMnet0.Furthermore, create a new network adapter and place it under NAT.

![image](https://github.com/user-attachments/assets/3cb099b2-6f62-46cc-8dac-e0e4d76e649b)

 
Run the pfsense machine.

![image](https://github.com/user-attachments/assets/1c02c7dc-fc7d-4f72-9131-b016c29f6c82)

 
After installation is completed it will show as the screenshot below

![image](https://github.com/user-attachments/assets/1a8909d0-6775-4c7f-a978-439c43f9c06d)

![image](https://github.com/user-attachments/assets/4c1ce924-de8b-43be-817c-76e8bab2d483)


 
For now, pfsense is installed and we are going to setup the active directory.

<h1>Part2: Setting up Active Directory</h1>
We have taken windows server 2019 as a server for setting up the active directory.

    https://info.microsoft.com/ww-landing-windows-server-2019.html
Similar to pfsense, keep on adding details and I have name this as ADDC01.

![image](https://github.com/user-attachments/assets/ef736242-e58b-4534-b967-c7a4a97d0315)

![image](https://github.com/user-attachments/assets/47853680-ea0f-4771-a139-efe7cba17b40)

 
It will take some time to install. After some time, it will tell you to enter password for the Administrator account. Then installation of windows 2019 is complete.

![image](https://github.com/user-attachments/assets/45730b44-d107-4abe-a90d-8934152f7e4d)

The first thing we are doing here is changing the computer name. 
Go to PC > Properties > Rename your PC in search and change it to ADDC01.

![image](https://github.com/user-attachments/assets/bfb675e9-1dc3-4c1c-aa46-ee33d27019cb)

 
After this it will tell you to restart the system.
The next thing we want to do is assign a static IP address. 
Open Network and Internet Settings > change adapter settings > Ethernet0 > Properties >IPV4 and click on Use the following IP Address.

![image](https://github.com/user-attachments/assets/c647623d-94cf-44f8-b287-2b407066143b)

 
After this going to the command prompt and typing the command

    ping 192.168.1.1

![image](https://github.com/user-attachments/assets/e532fe3b-5e8d-4556-80f7-65a1d195ddb3)

 
Now we can install Active Directory. 
Go to Server Manager > Manage > Add Roles and Features

![image](https://github.com/user-attachments/assets/0f1dbe92-e5ca-4e08-ad2d-fd2c8df4fef4)

 
This is the reason we changed everything on the above process. 
Click on Next and Select Role-based or feature-based installation.

![image](https://github.com/user-attachments/assets/71da20e8-41b6-42ae-a227-5eda5099d93a)

 
After this click on Next and Select Server Roles. Select Active Directory Domain Services and click next.

![image](https://github.com/user-attachments/assets/46d182e0-15a2-4db7-bc10-1401258b53ea)

 
Click on Install.

![image](https://github.com/user-attachments/assets/95ae09bc-fa78-4d71-b9d2-9bce9b35b867)

 
After installation is complete, click on promote this server to a domain controller. 

![image](https://github.com/user-attachments/assets/8a9c73a3-6704-487a-9d0d-f0868a345761)

Then click on Add a new forest and devraj.local as root domain name and click next.

![image](https://github.com/user-attachments/assets/825203aa-cc86-409b-9c01-245bc060895a)

 
After this enter password and others you can keep it as default.
![image](https://github.com/user-attachments/assets/e08c41d9-0041-472c-84a3-901c88f7ea53)

 
Then click Next until you see install.
![image](https://github.com/user-attachments/assets/eb12fd4a-e0f5-4a43-a7b0-e1fa403f6b49)

 
Then it will restart the machine.
Now we can add some users into the system. Go to Search > Active Directory Users and Computers > devraj.local > Users
![image](https://github.com/user-attachments/assets/c2cf24ee-531e-404e-b902-92f30f9254a8)

 
Instead of creating users into the Users tab, Right click into the Devraj.local > New > Organizational Unit
![image](https://github.com/user-attachments/assets/ae914773-b7b3-4fb0-a3b2-061f40f74ed5)

 
Here we are creating the organizational unit on the basis of IT, finance, and Sales.
Right Click on the organizational unit we just created and select New > User and add the users there. 
![image](https://github.com/user-attachments/assets/5ae978dd-6a11-4d38-8abb-b592fb53e18f)

 
Now open windows 10 machine which we have already installed earlier.
![image](https://github.com/user-attachments/assets/9b063485-b856-44d5-af59-8bead84d2a65)

 
After this Click on search > My PC > Rename this PC (advanced) > Change > Domain and enter our Active directory name which is Devraj.local. However it presented an error.

![image](https://github.com/user-attachments/assets/493fd2d8-aeb9-4381-bac1-ea0b46d667c8)

 
Here we have to make sure that the IP address of the windows 10 is in the same order as that of pfsense and ADDC01. For the windows 10 machine we have to keep the IP address static.

![image](https://github.com/user-attachments/assets/608650f1-ca50-4c03-9aad-7798f277a64a)

 
Making sure that the changes we made in making IP static is working or not.

![image](https://github.com/user-attachments/assets/fc2f4f8e-f2f5-403c-aef3-17d555838821)

 
From this we know that from windows 10 we can ping both the pfsense and domain controller however from domain controller we cannot ping windows 10. Here adding Devraj.local which is the domain name of active directory ADDC01. 

![image](https://github.com/user-attachments/assets/e034079d-8fdb-482a-a3dc-be24885d65a2)

 
After this it will display 

![image](https://github.com/user-attachments/assets/1200a811-c2d2-43f1-9ac4-38fc14063658)


And the system will restart.
We want to make sure that now the domain controller user that we made should be able to login in the windows 10 machine.

![image](https://github.com/user-attachments/assets/8ab420c1-88f5-446c-afe8-f2f6521374d4)

 
Here steven is the user we created in the active directory. Now we can log into the windows 10 using domain devraj.local of the active directory ADDC01.



<h1>Part3: Configuring Logging Policies </h1>
For this go to search > Group Policy Management > Forest > Domains > devraj.local
Right click on it and click Create a GPO in this domain, And Link it here.

![image](https://github.com/user-attachments/assets/a95ac8a7-b8d0-43ee-9229-9a48f7a3fa01)

 
For the name I have created Audit Policy – Endpoint and click ok.
After this right click on Audit Policy – Endpoint which we just created and click edit. Then go to Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies 

![image](https://github.com/user-attachments/assets/d39ed7f3-6987-457e-abd0-5b14ee53f2bc)

 
According to the Microsoft recommendation for baseline validation
1)	Account Logon
•	Audit Credential Validation – Success

![image](https://github.com/user-attachments/assets/8f5e6664-da78-47b9-9620-51b08218419c)

 
3)	Account Management
•	Audit Computer Account Management – Success
•	Audit Other Account Management Events – Success
•	Audit Security Group Management – Success
•	Audit User Account Management – Success

![image](https://github.com/user-attachments/assets/319781ea-28ee-45a9-a28f-579eab0aed54)

 
5)	Detailed Tracking
•	Audit Process Creation – Success

![image](https://github.com/user-attachments/assets/c05c74cb-d0e5-403f-83de-568e5cebc7e7)

6)	Logon/Logoff
•	Audit Logoff – Success
•	Audit Logon – Success, Failure
•	Audit Special Logon – Success

![image](https://github.com/user-attachments/assets/1f9ec026-e342-4c1c-b98a-96223156566b)


7)	Policy Change
•	Audit Audit Policy Change – Success, Failure
•	Audit Authentication Policy – Success

![image](https://github.com/user-attachments/assets/727b749c-4ddf-4ef2-b613-370f37d279cc)

 
8)	System
•	Audit IPsec Driver – Success, Failure
•	Audit Security State Change – Success, Failure
•	Audit Security System Extension – Success, Failure
•	Audit System Integrity – Success, Failure

![image](https://github.com/user-attachments/assets/bf9d4fd7-fe4d-49db-a189-15c2492a6c8f)

 
10)	After this click on Administrative Templates > System > Audit Process Creation > Include command line in process creation events. We are enabling this because when we enable Event ID 4688 which is process creation it will not show process command line which is vital for finding out which process was carried out.

![image](https://github.com/user-attachments/assets/daa8b008-7a3c-4862-b3f2-ad2f5b1b87a7)

 
12)	Click on Administrative Template > Windows Components > Windows PowerShell > Turn on PowerShell Logging and enable it. This is for Event ID 4104.

![image](https://github.com/user-attachments/assets/fb18238c-69ec-44ea-b729-62d99e8f2b8d)

 
14)	Finally, we should also enable Audit: Force audit policy subcategory settings.

 ![image](https://github.com/user-attachments/assets/384e1adc-d464-424c-b5a7-84bb6ef7fc9a)

 For checking out everything we change is working or not. Go to Windows 10 machine and run with steven user.
Open Event Viewer as Administrator. And filter for Event ID 4688 under Security.

![image](https://github.com/user-attachments/assets/c138f4cb-014a-4361-aa7f-c720fd87a087)

 
Looking out we were not able to see command line.
Now we are going to install and configure Sysmon to provide additional telemetry. In many environments, Sysmon or even EDR wouldn’t be available. This is why we have to know to enable proper logging on our machines to provide us with the telemetry to helps us with the investigation. Default settings in Sysmon is not enough.  
Download Sysmon.

    https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
    
It is a zip file so extracting the files.
Also go to the URL:

    https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml

and save the file and place it with Sysmon extracted file.

![image](https://github.com/user-attachments/assets/5f10fb1f-bc91-4a06-b4ee-ea6d096617ce)


After this opening the PowerShell in administrator we get:

![image](https://github.com/user-attachments/assets/98a543a6-5ef2-4087-9f63-9a11628bbcdc)

 
Click Agree. And it will get installed. Open Event Viewer in administrator and see whether Sysmon is installed or not. Go to Application and Services Logs > Microsoft > Windows > sysmon

![image](https://github.com/user-attachments/assets/7758ec65-903d-43be-921d-468c350e59d4)

 
And also, on Services we can see it is running.

![image](https://github.com/user-attachments/assets/32de1373-7f9f-4c6b-bf98-aa2b7f50b031)

 
For configuring logging policies this is the final step. Now we are going to Part 4 which is setting up Splunk.

<h1>Part4: Setting up Splunk</h1>
For this we have already installed splunk. {later needed to be added about the installation of splunk}

![image](https://github.com/user-attachments/assets/7784a2c8-7cd8-4d19-ba4a-a181a0c06e1e)

 
IP address of Splunk = 192.168.132.130
We know that this is not in our detection lab network. So we should assign a static IP Address.
   
    sudo vi /etc/netplan/00-installer-config.yaml 
                   sudo netplan apply
 
 ![image](https://github.com/user-attachments/assets/692238f6-a093-4d69-9015-5116c54a8c2b)


 Our static IP address is 192.168.1.20

 ![image](https://github.com/user-attachments/assets/01c93896-f9bc-4cfa-b094-f9a96e2cf261)

Now we are able to ping our firewall.

![image](https://github.com/user-attachments/assets/48436284-ed98-4e23-82a0-cdf918d37e86)

After the completion of above process, we can now open Splunk in windows 10 machine. Type:

    192.168.1.20:8000

![image](https://github.com/user-attachments/assets/4c5fd544-abcd-44b0-bbb4-065a48dda88b)


First, I will create a new index. For this go to Settings > Indexes > New Index.

![image](https://github.com/user-attachments/assets/63eb78b7-102e-48e1-85ea-c0708a293f6c)

 
Click Save. 
In windows 10, we want to share our data to Splunk. For this purpose, we would be installing a universal forwarder.
First download the universal forwarder from the Splunk website.
And also go to:

    https://github.com/MyDFIR/Active-Directory-Project
and copy the contents of Readme file and name it as inputs.conf and save it as All Files.
After this run the universal forwarder we just downloaded.

![image](https://github.com/user-attachments/assets/082bec95-6e91-4186-9d6b-20e744201667)

 
Click on Next. For the username I added admin as the username. We do not have deployment server so we just click Next. But we have receiver index and we put the IP address of Splunk there.

![image](https://github.com/user-attachments/assets/9fe4dee6-eb77-4718-8e48-dbfd41c6345a)

 
After the installation is done. Click on Splunk and go to Settings > Forwarding and Receiving > Configure Receiving > New Receiving Port and add 9997.

![image](https://github.com/user-attachments/assets/3ebc63a4-207a-4bde-92c7-69df8a95b231)

 
After the installation of Splunk universal forwarder is complete go to the folder 
C:\Program Files\SplunkUniversalForwarder\etc\system\local and copy the inputs.conf file we added from the GitHub to this location.

![image](https://github.com/user-attachments/assets/7db47071-a2ca-49a5-96fb-5a7740683278)

 
Right click on inputs.conf file. And make the changes as seen in the screenshot below and save it.

![image](https://github.com/user-attachments/assets/054cdbcc-0a88-4bb9-b68a-f00eee50466f)

 
Open Services as administrator and Splunk Forwarder > Log On> select Local System Account. Restart the Splunk Forwarder services.

![image](https://github.com/user-attachments/assets/2cd2e937-4c40-4505-907d-502bc7210511)

 
After the completion of above process, we can run the query in Splunk.
index=mydfir-detect

![image](https://github.com/user-attachments/assets/ed08175d-10a4-4647-940e-cae8ab7ffc7d)

 
Now our Splunk is able to get the data from windows 10. Now next thing to do is configuring the domain controller.
Performing the same thing that we did into the windows 10 to our Domain Controller. One of the easiest ways for sending our important file like universal downloader, Sysmon, inputs.conf is to create a network share. and also make sure that network discovery is turned on.
In windows 10:

![image](https://github.com/user-attachments/assets/e86b0ac9-e3cf-4816-bf9f-e23972fe291b)

 
And in Domain controller, 

![image](https://github.com/user-attachments/assets/5f3dbd32-28f9-4f4c-88d9-ed4485b128b7)

 
After this copy the files into the system.
Now perform everything we did into the windows 10 like installing Sysmon, Splunk universal forwarder and also placing the input.conf file into its destination. After everything on Active Directory is done, then on splunk we can see whether we have two hosts there or not.

![image](https://github.com/user-attachments/assets/217af8ce-6c01-407f-a2f7-571e7b9904ee)

 
<h1>Part 5: Configure Zeek and Suricata</h1>
For Zeek and Suricata virtual machine, I will install an ubuntu machine with its name zeekandsuricata.
Opening Zeek and Suricata from our virtual machine. 
IP Address of zeek_suricata = 192.168.132.138

![image](https://github.com/user-attachments/assets/e94404e9-a38b-463c-bcd1-338c7b5535c6)

 
After this opening the system in putty or mobaxterm.

![image](https://github.com/user-attachments/assets/ccb69037-84cb-44a8-916b-a9f6f275a9ae)

 
After this we are going to install zeek. Our ubuntu version is 22.0.4. Go to the website and select your ubuntu version and install it.

    https://github.com/zeek/zeek/wiki/Binary-Packages
Mine is 22.04
     
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    sudo apt update
    sudo apt install [zeek, zeek-6.0, or zeek-nightly]

 ![image](https://github.com/user-attachments/assets/822d8389-340c-4040-ad57-9fa5be8721e8)

Zeek is located under the following directory

    cd /opt/zeek/bin
To customize zeek it uses the configuration file that is located under the above directory.

    sudo vi /opt/zeek/share/zeek/site/local.zeek
![image](https://github.com/user-attachments/assets/00f42291-0911-4084-a2d0-042c936127b7)
 
Add these two lines in the bottom of the page

 ![image](https://github.com/user-attachments/assets/07b3dba9-28bc-4e58-9f6e-34521f64523d)

After this our configuration file should be updated with our ja3 and ja4 hashes. 
Now we are going to install JA3 and JA4 for zeek.

Setup JA3 for zeek:

    sudo apt install zkg
    zkg install ja3

Edit the local.zeek config in /opt/zeek/share/zeek/site/local.zeek and add in @load ja3

![image](https://github.com/user-attachments/assets/85c3635e-b244-48ac-88c4-4bb9cd8528c5)

Setup JA4 for zeek:

    zkg install zeek/foxio/ja4

![image](https://github.com/user-attachments/assets/95efe470-d4a1-4f62-9f4f-aebd694efaba)

Change the local.zeek config in /opt/zeek/share/zeek/site/local.zeek and add in @load ja4plus

![image](https://github.com/user-attachments/assets/4a41a2f2-5e9b-4b8b-a844-8729c392c3a5)

This is the main file for the installation of zeek in the virtual machine.
Now we are going to install Suricata which is the IDS Intrusion Detection System.

Add Silver C2 rules for Suricata

    sudo apt -y install libnetfilter-queue-dev libnetfilter-queue1 libnfnetlink-dev libnfnetlink0 jq
    sudo add-apt-repository ppa:oisf/suricata-stable
    sudo apt install suricata
    sudo systemctl enable suricata.service
    sudo systemctl stop suricata.service

We want to configure yaml file for its configuration file on Suricata. And this is located under the directory. And make sure that the community-id is set to true.

    sudo vi /etc/suricata/suricata.yaml 

![image](https://github.com/user-attachments/assets/99783539-a8d3-4adb-a52d-fa2a5fa03985)

Suricata Rules

    sudo suricata-update
    sudo suricata-update - Update Rules
    sudo suricata-update list-sources
    sudo suricata-update enable-source tgreen/hunting
    sudo suricata-update enable-source et/open
    sudo suricata-update - Update Rules
    sudo systemctl start suricata.service
    sudo suricata -T -c /etc/suricata/suricata.yaml -v - Validating Suricata
    /var/lib/suricata/rules/ - Rule Location
![image](https://github.com/user-attachments/assets/d558c954-d0c1-4375-b233-551a3e6cc155)
 
Immersive Labs

    wget https://raw.githubusercontent.com/Immersive-Labs-Sec/SliverC2-Forensics/main/Rules/sliver.snort

After all this process completed, type

    ip a

 ![image](https://github.com/user-attachments/assets/e50e75f5-7ae1-4849-bbf7-31694531d544)

We know that this is not in our detection lab network. So, we are assigning a static IP Address.

     sudo vi /etc/netplan/00-installer-config.yaml 
                   sudo netplan apply

 ![image](https://github.com/user-attachments/assets/1d6d43bb-6e9b-4d6f-ba1c-b2c622e1a849)

After this we can ping to our splunk server and we can ping it perfect.

![image](https://github.com/user-attachments/assets/7fc7678c-814d-4284-8d10-1b5ccd21eb5f)

 
Go to the splunk website and copy wget link for universal forwarder for sending data from zeek_suricata to the splunk.

![image](https://github.com/user-attachments/assets/dfabc001-82eb-45f3-91f6-349485e2e051)

 
Since the URL is too long we can use it a service called tinyurl. Just copy the link in tinyurl and shorten URL there.

![image](https://github.com/user-attachments/assets/1394aed7-8540-4d38-9a3e-bb7f228cbe7e)

 
Then in our virtual machine we can write:

    sudo wget https://tinyurl.com/mydfir-detect12

 ![image](https://github.com/user-attachments/assets/27b9a586-c366-4170-b8ae-422dad6ca35a)

After this we are going to install the deb file.
   
    sudo dpkg -i mydfir-detect321
 
![image](https://github.com/user-attachments/assets/a20d004b-a961-4e7b-9b8f-be6f55f0d0fe)

![image](https://github.com/user-attachments/assets/937f2c3d-1407-4cbf-a2e3-8f4ec9906e31)

 
Here looking at the above screenshot we know it is owned by username splunkfwd. We are going to change into it.

    sudo -u splunkfwd bash
    ./splunk start

 ![image](https://github.com/user-attachments/assets/fe510004-8305-4538-8eb8-d7b7254c1397)

It will tell you to enter username and password. And make sure that your splunk is enabled.

![image](https://github.com/user-attachments/assets/c92c2481-2a08-4118-8ad7-c301f35e95ba)

 
Now we have to point our zeek-suricata server to splunk server. For this

    sudo ./splunk add forward-server 192.168.1.20:9997
    sudo ./splunk list forward-server

![image](https://github.com/user-attachments/assets/f49b0562-8727-4c90-9b1d-c310ce932dd1)


The second command is used in order to make sure the changes we made using above command is working or not. Now we can go into the user splunkfwd and start the splunk. However we have active forwards to none.

    sudo -u splunkfwd bash
    ./splunk start

 ![image](https://github.com/user-attachments/assets/a41fc387-e57e-4526-b9a3-1e33860d20bc)

we can see active forwards changed after writing the command below:

    ./splunk list forward-server

![image](https://github.com/user-attachments/assets/0c23f529-35ae-445c-aed3-98f1970a9396)
 
This is how we configure Splunk on our zeek-server to point our data over to the Splunk server. Now we need to configure our inputs.conf file, which will be responsible for sending all of the Zeek logs over to our Splunk and to do that first I will exit out and create an inputs.conf file under the etc/system/local for Splunk. So, writing the command:
sudo vi /opt/splunkforwarder/etc/system/local/

![image](https://github.com/user-attachments/assets/cf2880e3-4869-4d16-8ee6-ba6a193ec42d)

 
Now we need to got to 
cd /opt/zeek
cd logs 
however, we get permission denied.
So changing the user to root.
sudo su

 ![image](https://github.com/user-attachments/assets/3151e659-0e35-484a-8ed1-8df78c9b9f48)

After this finally we can go to the logs directory.

![image](https://github.com/user-attachments/assets/74c3249c-8940-4ab5-83b1-5a932a3c896a)

 
Furthermore, I need to change my network to promiscuous mode. In promiscuous mode, the NIC allows all frames through, so even frames intended for all other machines or network devices can be read. We recall that Zeek and Suricata is there to listen in on traffic, so that is why we need to have our network adapter or network interface card set to promiscuous mode.

    sudo ip link set ens33 promisc on

![image](https://github.com/user-attachments/assets/79a5a0e2-e5a4-4565-8012-75b4da71fc9d)

 
After all these configurations we made, we want to make sure that Zeek and Suricata are running properly. 

![image](https://github.com/user-attachments/assets/66e3ed62-120a-42db-b445-aceb250edfe3)

 
We make changes to the host=192.168.1.30 and interface=ens33

![image](https://github.com/user-attachments/assets/21989b9c-5e57-447c-8dcb-934384cc762d)

 
After we make these changes we are going to deploy it by using the command:

    sudo /opt/zeek/bin/zeekctl deploy
 
 ![image](https://github.com/user-attachments/assets/2e105097-cd8d-49ba-a72a-03037ebed144)

![image](https://github.com/user-attachments/assets/be79ac92-f7c4-4ade-bae0-635d9e57c50d)

 
Inside of current folder we can see a lot of logs like conn.log, ssl.log, known_hosts.log and many more.

![image](https://github.com/user-attachments/assets/22d8bb01-9add-4472-bd07-a627770d85d3)

 
Now zeek is good to go. Shifting towards Suricata, its logs are found in 

    cd /etc/Suricata
    sudo vi Suricata.yaml
![image](https://github.com/user-attachments/assets/38a06814-ea26-4463-ad17-a01d8f0fcfc2)
    
 Here in the suricata.yaml file change the eth0 to ens33. There are 3 interfaces having eth0. So change it to ens33.

 ![image](https://github.com/user-attachments/assets/e5deb084-10ea-4c50-9eac-0b635c7ca47a)

After this run

    systemctl restart suricata.service



 
In Suricata logs are stored in /var/log/suricata/
 
Running the command and making changes to inputs.conf file.
 
 
We are gonna make changes in the local.zeek file in order to making sure that the sourcetype file we get will be in json format.
 
 
After that we run the command
sudo /opt/zeek/bin/zeekctl deploy
 
Now zeek should start outputting its logs in json format. Now we have successfully configured our zeek and making changes for Suricata. Going to inputs.conf file again.
 
After this 
Sudo -u splunkfwd bash
Cd /opt/splunkforwarder/bin
./splunk stop
./splunk start
Now when we head to the windows machine we should be able to see some logs of zeek.
 
Part6: Configure PFSense
For pfsense, opening the pfsense in the windows 10 in browser.
 
Default username and password for pfsense is admin and pfsense respectively.
Click on Next.
Make sure this is checked off.
 
What I want to do with pfsense is that sending syslog over to our Splunk server and install SquidProxy. That way we can take a look at any proxy logs and then forward those proxy logs over to our Splunk server.
First I want to install SquidProxy before sending syslog over to our Splunk server. To install our proxy, go to System>Package Manager > Available Packages and search squid.
 
 
Then going to pfsense in virtual machine. Enter 8 to shell. Here we are installing Splunk universal forwarder similar to what we did into the windows machine. Going to Splunk universal forwarder and copying the URL. For pfsense it uses Free BSD.
 
Then going to tinyurl.com and shortening the URL.
 
Pfsense uses fetch instead of wget.
fetch https://tinyurl.com/mydfir-detect2
 
Then we are going to extract the file using the command below which will create a folder splunkforwarder.
tar xvzf mydfir-detect2
 
 
 
Let’s create an inputs.conf file
cd ..
cd /etc/system/local
ls
vi inputs.conf
 
 
Now we need to restart our splunk
Cd ../../../bin
./splunk stop
./splunk start
After this we can see logs of pfsense in the Splunk. Here we can see logs of pfsense are not parsed properly. For that we can install an application called ta-pfcents.
 


Part7: Generating Telemetry
Installing the kali linux in the vmware workstation. 
https://www.kali.org/get-kali/#kali-virtual-machines
 
The IP address is not in the range of our lab. So we are going to change the IP Address to static.
Go to Settings>Advanced Network Configuration>Wired Connection 1> IPV4 settings and set the method to manual.
 
Now the IP is changed to 192.168.1.250
 
So now I am going to create a basic malware to allow my windows machine to execute it, which will then establish a C2 connection back to my kali machine. For that I will be using msvenom.
 
The only reason we are doing this so that we can additional telemetry on the windows 10 machine, so that we can see that it in Splunk. Now opening msfconsole which is the Metasploit Framework console.
 
 
Then type exploit and here we are listening to that port
 
Opening the another tab on terminal.
python -m http.server 9999
Now going to windows 10 machine and typing 192.168.1.250:9999 in browser we get Invoices.docx.exe file. Make sure to disable windows defender. Now download the file.
 
Download this file and run it and head back to the kali machine. Meterpreter session is started.
 
Now we can do anything as we have full control of windows 10 machine. For this I am going to download desktop.ini file in Desktop of Kali from windows 10.
 
Furthermore performing nmap scan to create more telemetry.
 
Now when seeing in our splunk we can see every event that happened.
 
