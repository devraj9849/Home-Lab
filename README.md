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

 
