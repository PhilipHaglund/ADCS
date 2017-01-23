Active Directory Certificate Services
===================
This my take on a simple yet powerful Active Directory Certificate Services (ADCS) implementation. 
The two PowerShell scripts provides an easy and documented process to install, configure and setup a complete two-tier PKI environment.

![PKI Overview](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/0_PKI.png)


----------


Requirements
-------------
- An Active Directory Directory Service
- A Windows 2012/2012R2/2016 Server* (*PowerShell 4.0*) used for Root/Offline CA
- A Windows 2012/2012R2/2016 Server* (*PowerShell 4.0*) used for Enterprise/Subordinate CA
- Domain Administrator membership or similar privileges for installation.
- Local Administrator privileges (*PowerShell.exe Runas Administrator*).

> **Servers can be hosted in a virtual environment.*

Installation
-------------

 1. Run "Install-ADCSOfflineCA.ps1" on the server dedicated for the Root/Offline CA Role.
 ![Install-ADCSOfflineCA.ps1](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/1_PKI.png)
> - **Company:** Used to populate the and AIA/CRL and CA Common names.
> - **DomainURL:** Used for CDP and AIA publishing.
> - **ConfigNC:** Used for publishing Root CA in the Active Directory.


 2. Confirm the installation when/if prompted. The installation of the Root/Offline CA Role is now done.
 ![Root CA Installation fininshed](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/3_PKI.png)

 3. Run "Install-ADCSSubordinateCA.ps1" on the server dedicated for the Enterprise/Subordinate CA Role. ![Install-ADCSSubordinateCA.ps1](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/4_PKI.png)
> - **SMTPServer:** Mail server used to send the PKI maintenance/job reminder.
> - **ToAddress:** Recipient address for the PKI maintenance/job reminder.
> - **FromAddress:** Sender address for the PKI maintenance/job reminder.
> - **City:** Used to populate the ADCS Web Enrollment information template.
> - **State:** Used to populate the ADCS Web Enrollment information template.
> *Country is not available as a parameter as of now, default is Sweden. *
> *ADCS Web Enrollment Template can easily be modified in the $env:WinDir\System32\certsrv\certdat.inc file. *

 4. Each next setup provides a prompt that encourages a manual routine / process.
 4.1. Create an Internal DNS-Zone and/or an A-record pointed to the Enterprise Subordinate CA server.
 *It's highly recommended to create an external publishing for the $DomainURL so the CDP is reachable from the outside.*
 ![Create a DNZ-Zone](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/7_PKI.png)


 4.2 Sign/Issue the Enterprise/Subordinate CA Certificate on the Root/Offline CA server.
 *It's recommended to not have a network connection on the Root/Offline CA Server when running in production. *
 ![Issue Subordinate CA](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/8_PKI.png)

 Example Submit request:
 ![Example Sign/Issue](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/9_PKI.png)


 4.3 Publish a new CRL on the Root/Offline CA server.
 ![enter image description here](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/16_PKI.png)

 Example: 
 ![Example New CRL Publish](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/17_PKI.png)


 4.4. Rename the Root/Offline CA Certificate to match the AIA location.
 ![Rename Root CA certificate](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/18_PKI.png)


 4.5. Copy the CRL and CRT files from the Root/Offline CA server to the Enterprise/Subordinate server.  
 ![Copy CRL and CRT files](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/21_PKI.png)


 Example:

 ![Example Copy](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/22_PKI.png)


 4.6. Unzip / Move the copied CRL and CRT files (*Step 4.5*) to the correct paths on the Enterprise/Subordinate CA Server. 
 ![Move CRL and CRT files](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/23_PKI.png)


 4.7 Automatically trying to add the Root/Offline CA certificate to the Active Directory Configuration.
 ![Add Root CA to Active Directory](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/27_PKI.png)

 View in adsiedit.msc after Step 7 (*4.6)*.
 ![AD ConfigNC](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/28_PKI.png)


 4.8. Install the Enterprise/Subordinate Certificate.
 ![Install Subordinate Certificate](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/29_PKI.png)

 Example:

 ![Install CA Certificate](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/30_PKI.png)

 4.9. Automatically modifying "certdat.inc" file to match the Company information.
 ![Modify certdat.inc](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/32_PKI.png)


 4.10. Create a Group Policy for Certificate  Auto Enrollment (*Only recommended*).
 ![Create Group Policy](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/33_PKI.png)


 Installation is now done.
 ![Installation finished](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/39_PKI.png)

 Verify the setup in pkiview.msc.
 ![pkivewi.msc](https://raw.githubusercontent.com/PhilipHaglund/ADCS/master/images/41_PKI.png)



> For a more detailed installation check the soon to be updated [Wiki section.](https://github.com/PhilipHaglund/ADCS/wiki)
