Node.js on Windows Server 2012: Setup Guide
---

# Let's begin!
Acquire a Windows Server 2012 image; whether VM, physical box, or cloud mount makes little difference. Make sure IIS is installed, then download and install the Application Request Routing extension from Microsoft:
http://www.iis.net/downloads/microsoft/application-request-routing
We'll come back to IIS later, when it's time to configure it.

On our servers, we run our Node apps as Windows services, and simply proxy requests to them through IIS (after IIS handles the HTTP security), we'll need a helpful tool to let us generate and maintain our service configuration. Enter NSSM:
http://nssm.cc/download
Simply download it and extract nssm.exe from the appropriate folder (win32 v win64) to C:\windows\ - this automatically adds it to the path. You don't need to do this for a local development VM, just for a server.

In order to manage Node, we aren't using the default available download from nodejs.org; instead, we're using a Node version manager called nodist. Download it here:
https://github.com/marcelklehr/nodist/zipball/master
Unzip the folder to C:\ and rename it to "nodist." The goal here is to get the Node executable at the path
````
C:\nodist\bin\node.exe````
Once it's there, open a command prompt (using Run As Administrator) and issue these two commands:
````
C:\> setx /M PATH "C:\nodist\bin;%PATH%"
C:\> setx /M NODIST_PREFIX "C:\nodist"````
Close the command prompt and open a new one -- otherwise, the settings you just created may not be reflected. Run this command to download the actual Node executable.
````
C:\> nodist selfupdate````

Some internal stuff in Node requires Python 2.6 or 2.7 -- Python 3+ isn't compatible with Node as of today. Download and install it from
https://www.python.org/downloads/
Make sure to check "Install for all users" and enable "Add python.exe to Path" inside the installer.

A couple of functions within the API require a third-party graphics tool. I've selected GraphicsMagick, due to its license, simple integration, maintenance activity, and performance. Grab it here:
http://sourceforge.net/projects/graphicsmagick/files/graphicsmagick-binaries/
Download the latest version that reads Q8 and x64. Q16 is overkill for our purposes, intended for ultra-high-resolution graphics, and very very CPU intensive. At the end of the installation wizard is an installation test. Perform it. If it didn't work, you've done something wrong and may need to start completely over.

The last thing to download and install is git, the version control software client.
http://git-scm.com/download/
Install it with the default options. Do not select the option to "Use Git and optional Unix tools from the Windows Command Prompt." This is very, very dangerous and may result in system instability.

One last thing for a local VM setup: Make sure your VM is configured to use "NAT" for networking. In VMWare Player, it's configured under "Player > Manage > Virtual Machine Settings > Network Adapter" 

# Now let's grab the source code!
First, make a folder to hold the code: C:\builds\
Launch "Git Bash" from the start menu and issue these commands:
````
$ cd /c/builds
$ git clone https://github.com/YourAccount/YourRepository.git yourApp (note: you'll be prompted for git login info)
````
If you use submodules in your application, issue these commands too:
````
$ cd yourApp/
$ git submodule init
$ git submodule update (note: you'll be prompted for git login info)
$ npm update
````

# Back to IIS, it's time to configure!
In the "Application Request Routing" IIS module, choose "Server Proxy Settings" on the right, and check "Enable Proxy." Disable the Disk Caching and leave the rest of the settings alone.

If you've been issued an SSL cert, import it into IIS using the "Server Certificates" module at the Home screen in IIS Manager.

Create an application pool for Node apps with the "No Managed Code" option.

Create two sites, one for API and one for OAuth. If you've got an SSL cert, give them their HTTPS bindings, using the certificate you've imported. If not, just set them up with regular HTTP bindings. Assign them to the Node application pool, and point them to any directory; you may (and maybe should) use the source checkout directory for each. For any server, choose "Connect As..." and specify the proper service account and password.

Inside each site, choose the "URL Rewrite" module and click "Add Rule(s)...". Choose "Reverse Proxy" and specify the rewrite URL as such:
http://127.0.0.1:8301/{R:1}

Check "Log rewritten URL" and save.

# Open some ports!
Open Windows Firewall and create a new Inbound Rule, opening TCP ports 8300 to 8310. Find the rule called "World Wide Web Services (HTTP Traffic-In) and make sure it's enabled. If you've got an SSL certificate, find the rule called "World Wide Web Services (HTTP***S*** Traffic-In) and make sure it's enabled.

# Set up the services!
This is only for a Node.js app server, not for a local development VM. If you're configuring a local dev VM, skip this part.

Open a command prompt and issue this command: 
````
C:\> nssm install yourNodeService````
A GUI will pop up. Fill out the screens as follows:

- Application tab:
  - Path: `C:\nodist\bin\node.exe`
  - Startup directory: `C:\builds\yourApp`
  - Arguments: `.` (note: if you're specifying any kind of environment parameter in the arguments, here's where it goes)
- Details tab:
  - Display name: Whatever you wish to call your service
  - Description: (anything, I leave it blank)
  - Startup type: Automatic
- Log on tab:
  - (X) This Account: (use the appropriate account for your environment)
  - Password & Confirm are **REQUIRED** or the service will not work. If you wish to edit the service, you must know the password.
- Dependencies, Process, Shutdown tabs:
  - Ignore these.
- Exit actions tab:
  - Delay restart by 1 ms.
  - Leave the other settings alone.
- I/O tab:
  - Input: leave blank
  - Output: `C:\builds\yourApp\logs\stdout.log`
  - Error: `C:\builds\yourApp\logs\stderr.log`
- File rotation tab:
  - [  ] Replace existing Output and/or Error files
  - [X] Rotate Files [X] Rotate while service is running
  - Restrict rotation to files older than 86400 seconds (one day)
  - Restrict rotation to files bigger than 41943040 bytes (40 MB)
- Environment tab:
  - Ignore this.

Click "Install service" and wait a second. Confirmation should appear in the command prompt you opened. 
Repeat this process for every Node application you use, substituting the proper names and folders where applicable.

# Wait, I'm setting up a local VM!
Then ignore the whole services section above, as instructed. Instead, open a command prompt and issue this command:
````
C:\> npm install -g nodemon````
Simply use nodemon at the command prompt whenever you're developing, instead of node. It will watch your files for changes, and restart when it sees changes.

# Start the apps!
If you've done everything correctly, you should be able to verify that the apps run from their folders. Make sure you've got one command prompts open per Node application, awaiting commands in the Node application folder.

Sometimes this crashes on a cryptic error like "ENOTFOUND" or "ENOADDR" -- should that happen, it's because the hostnames specified in the apps' config files aren't managed by DNS and pointing to the machine you've set up. If you need the DNS entries, that's up to you to figure out. If you don't, just open your hosts file and add a line like
````
127.0.0.1  yourapp.yourdomain.tld````

If you've been setting up a server, start each Node application service through the services console or by issuing  commands such as these at a prompt:
````
C:\> net start yourapp````

# Good to go!
Congrats, you're all set up. If this was a server, you're done! Good job! Verify that it's running and available by pointing your local hosts file at it and submitting a request through some kind of API testing tool, like Postman, a Chrome extension.

# But wait, there's more!
If this is a local development VM, install Chrome and Postman and Sublime Text or whichever code editor you prefer to use. Here's a list of file extensions you'll want to associate with your editor:
````
.js             javascript
.json           javascript object notation
.md             markdown
.gitignore      ignore file for git repositories````

You'll also want a different user than Administrator, since our Node apps never run under the administrator profile from any server, and it's just good policy. Create a separate user with Administrator privileges, since you'll need them as a developer, and use that account to develop under. Nobody else needs to know your local VM username or password, nor should they. Just use it and stay safe.

# Okay, that's it! Get out of here! You're done! Show's over! Good day! I SAID GOOD DAY!