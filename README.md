# Project Writeup
###Overview
Cryptography challenges are popular in Capture the Flag (CTF) competitions and many of them involve exploiting a vulnerability in a poorly implemented RSA cryptosystem. These vulnerabilities make it possible to either factor an RSA modulus in a reasonable amount of time or compute the plaintext message directly.  Often the workflow for solving one these RSA problems involves figuring out which vulnerability is present, researching exploits for that vulnerability, and writing a program/script implementing an exploit. Assuming that the vulnerability is not revealed in the problem statement, each of these steps can take a significant amount of time. On top of that there is also the time spent debugging the exploit implementation.  

To help reduce the amount of time spent on each of these steps, we have developed an RSA exploit library for CTF challenges related to RSA cryptosystems. Many commonly known exploits, including Wiener's Attack, Hastad's Broadcast Attack, Common Modulus attack are already implemented for the user. In addition, various prime factorization methods each with their own special use cases are included. If the required exploit is already implemented by our library, the time required to research, code, and debug a solution is significantly reduced. If the RSA vulnerability or required exploit is not immediately known, a user could run a battery of exploits against the provided ciphertexts and RSA key data in an attempt to uncover more information. Moreover, a RSA problem may be vulnerable to more than one attack, which may be unknown to both user and problem author. Thus, the library can also be used to test CTF challenges for correctness, thus reducing the amount time required to implement solution scripts. 


###Existing Research/Work
##### 1. Twenty Years of Attacks on the RSA Cryptosystem
This paper provides a survey of many potential vulnerabilities in the RSA cryptosystem and describes the exploits for each. Among the discussed exploits are common modulus, Wiener's attack, Boneh Durfee attack, Hastad's Broadcast attack, and Franklin-Reiter Related Message attack. We used this paper as a basis for determining which exploits to include in our library. 
#####2. https://github.com/pablocelayes/rsa-wiener-attack
Github user pablocelayes has written a collection of python scripts that implement Wiener's
attack on RSA. When the private exponent(d) is less than N^(1/4), Wiener's attack can use continued fraction approximations to recover d.
#####3 https://github.com/mimoo/RSA-and-LLL-attacks
Github user mimoo appears to have written a collection of sage scripts that implement LLL
lattice based attacks on RSA. LLL lattice reduction is an algorithm created by Coppersmith
that can be used for finding roots of polynomial equations. His implementation of Boneh Durfee's attack is included in our library.
#####4 http://ahack.ru/write-ups/ructf-quals-14.htm
User Black Fan provided an implementation of the Franklin-Reiter Related Message attack that we modified to be more general.
#####5 https://github.com/rk700/attackrsa/tree/master/attackrsa
Github user rk700 has written implementations for both Hastad's Broadcast attack and the Fermat factorization method. Our library's implementations of both exploits were derived from his work. 

###Approach and Implementation
##### Introduction
During our research, we were unable to find a single library or tool that presented RSA exploits in coherent and easy to use fashion. We did find many implementations of RSA exploits that various CTF competitors around the world had posted in their writeups. However, many of them were coded in such a way that they were specific to the problem being solved and could not be applied to other problems. The implementations that were coded to be general often required  different sets of parameters and it was unlikely that implementations for two different exploits would provide a common interface. To solve these issues, we decided to develop a library that provided both general implementations of various exploits for RSA vulnerabilities and a uniform interface through which these exploits could be run. 

##### Architecture
We implemented a class called RSAData to store all of the information associated with a particular RSA challenge, i.e. ciphertext plaintext pair and the RSA key elements used to manipulate that text data. At the moment, RSAData is implemented as a combination of the RSAObj class from pycrypto and a simple TextData class that we implemented ourselves. The RSAObj class is used to store and create all of the RSA key elements. This includes the modulus N, public exponent e, private exponent d, and primes p and q. We leveraged RSAObj's preexisting functionality for encryption and decryption. The TextData class stores the ciphertext, plaintext, and an ID number. Some of the exploits in our library only work if all ciphertexts were generated from the same plaintext. TextData objects with the same ID number contain ciphertexts that were generated from the same plaintext. The ID number field must be set by the user. 

Each exploit is implemented as a class that extends a base Exploit class. The base Exploit class only exports one method called run that takes two parameters. The first parameter is a list of RSAData objects and the second is a dictionary that can be used to specify additional information for particular exploits. For example, the Franklin-Reiter exploit requires a polynomial that specifies the relationship between two plaintext messages that were used to generate known ciphertexts. The presence of the run method provides a common interface that a user can use to call any exploit after the list of RSAData objects has been populated. Extracting the required information from the RSAData objects is handled by the run function and any subroutines called from there. 

##### Usage
We envision the common workflow as follows, first, the user will initialize a list of RSAData objects using information from the problem. Initializing an RSAData object reqires first initializing an RSAObj and a TextData object. The RSAObj should be initialized using our rsa_obj function which is actually a wrapper for pycrypto's construct function. The parameters to this function are as follows:

```
n: RSA modulus
e: public exponent
d: private exponent
p: first prime factor
q: second prime factor
```
All of the above parameters are long type.

n and e are required parameters while the others are optional. We expect that in most CTF problems, the user will only provide n and e. 

The parameters to the TextData initializer are as follows:
```
c: ciphertext
m: plaintext
idnum: ID number identifies plaintext, two TextData object containing cipertext corresponding to same plaintext, have same idnum.
```
All of the above parameters have an integer type (they don't have to be explicitly declared as long type).

None of these parameters are required and even the TextData object itself is an optional parameter in the RSAData init function. However, many exploits require ciphertexts, so the user needs to specify c and idnum in those cases.

An example of initializing a RSAData object is shown below:
```
import RSAExploits

n = #value
e = #value
c = #value
idnum = #value

rsaobj = RSAObj(n, e)
txt = TextData(c_text=c, idnum=idnum)
rsadata = RSAData(rsaobj, txt)
```

After the users have initialized a list of RSAData objects, they have two options. They can, either run a predefined list of exploits against their RSAData objects, or they can specify the desired exploit manually by instantiating a class for that exploit and invoking its run method. Examples of both scenarios are shown below:

```
# Run a predefined list of exploits 
rsadata_list = []  # Assume this list has already been populated
rsa_cracker.init()
rsa_cracker.attack(rsadata_list)
```

```
# Specify an exploit to run
rsadata_list = []  # Assume this list has already been populated
exploit = Common_Modulus()
exploit.run(rsadata_list)
```

The run function in each exploit attemptS to uncover missing information in each RSAData object in the provided list. For all of the currently implemented exploits, this means either recovering d,p, and q (private exponent and prime factors) or the plaintext message m. Any recovered information is updated in the corresponding RSAData object. If a run function is able to uncover any information in any of the RSAData objects, it returns True. Otherwise, it returns False. If a run function returns True, most CTF players would then want to know what the recovered flag is. Often, this flag is a string. If the successful exploit recovered the private exponent d, the user would first need to decrypt the ciphertext before attempting to print the message. If the successful exploit recovered the message, the user would just need to convert the plaintext from an integer form to ASCII. Examples of both scenarios are shown below:

```
# Exploit recovered the private exponent d
rsadata.decrypt()
print num2string(rsadata.get_m())
```

```
# Exploit recovered the private exponent d
print num2string(rsadata.get_m())
```

num2string is a function included when the user imports RSAExploits and it converts an integer to its hex representation and then interprets it as ASCII. 

Some of the exploits require extra information that did not fit cleanly into the RSAData object. To handle these special cases, a second optional parameter is accepted by each exploit's run() function. This parameter is a dictionary containing key-value pairs where the key is a string that is equivalent to the name of an exploit class and the value is the extra information required. For example, the Franklin-Reiter exploit requires a polynomial that describes the relationship between two plaintext messages that produced two known ciphertexts. The documentation for individual exploits should be checked to see if they require any extra information. An example usage of the dictionary is shown below:

```
from sage.all_cmdline import *
rsadata_list = []  # Assume this list has been populated
n = some_value
x = PolynomialRing(ZZ.quo(n*ZZ), 'x').gen()
poly = x - 5
info_dict = {}
info_dict["Franklin_Reiter"] = poly
Franklin_Reiter().run(rsadata_list, info_dict)
```

##### Exploits
At the moment the following exploits/factorization methods are available:
* Boneh Durfee attack on low private exponents
* Common Modulus 
* Common Factor (common prime factors in moduli)
* ECM Factorization (special condition: one of the primes should be much smaller)
* Fermat Factorization (special condition: p and q are very close together)
* Franklin-Reiter Related Message attack (special condition: relation between messages)
* Hastad's Broadcast attack (special condition: number of RSAData should be greater than or equal to e)
* Quadratic Sieve Factorization (2nd fastest general purpose factoring algorithm)
* Wiener's attack (special condition: low private exponent)

##### Expansion
Adding new exploits to our module is pretty straightforward. A new .py file should be created and placed in the exploits folder, that declares a new class extending Exploit. This new class must implement a run function that applies the exploit to a list of RSAData objects, and optionally uses the dictionary to receive extra information.

##### Sage
Some of the included exploits in the library require sage to run. For example Franklin_Reiter relies on Sage's ability to handle polynomials. However, Sage is not required to use our library. If the user attempts to run any exploits that require Sage, an error message will be printed. Exploits that do not require Sage will run just fine.

##### Installation
From command line run the following:
```
sudo apt-get update 
git clone https://github.com/vik001ind/RSAExploits.git
sudo pip install RSAExploits/

# If sage is installed, run the following commands as well
cd RSAExploits/
sudo sage -python setup.py install
```

##### Pylint
At the moment we are ignoring any errors concerning variable names or imports from sage. We know that the error messages about imports from sage are not correct and we feel that many of the variable names (eg: N, e, d) are named appropriately given the context of RSA. 

###CTF Problem examples:

####CTF Problem: Hack You 2014 - CRYPTONET:
We have intercepted communication in a private network. It uses a strange protocol based on RSA cryptosystem.
Can you still prove that it is not secure enough and get the flag?

Analysis of server RSA implementation and capture file:
* Integer encoded plain-text message is less than modulus
* Public exponent(e) remains constant (17), but modulus(N) varies
* 19 ciphertexts are captured

This cryptosystem is vulnerable to Hastad's Broadcast Attack. Hastad's attack uses the Chinese Remainder Theorem to recover the plaintext message given a list of ciphertexts, moduli, and the public exponent e. It is guaranteed to succeed if the same plaintext message was used to generate all ciphertexts, the public exponent e is the same in all encryptions, the number of ciphertexts is greater than or equal to e, all of the moduli are greater than the plaintext, all of the moduli are unique, and all of the moduli are coprime (if they are not coprime then they share a common factor and another exploit can be used). Ideally, a user needs to extract the ciphertexts, moduli, and public exponent from the packet capture file and provide that information to our library. Our library would run through a list of exploits that includes Hastad's attack and would recover the plaintext. If the user realizes that the correct exploit is Hastad's attack, they could specify the correct exploit and not have to wait for all of the other exploits to finish executing. The corresponding script might resemble the following:

```
from RSAExploits import rsa_cracker
from RSAExploits import RSAData
from RSAExploits import rsa_obj
from RSAExploits import TextData
from RSAExploits import num2string
from RSAExploits import Hastad
import sys

sys.setrecursionlimit(10000)

# Parse and store all of the ciphertexts provided by the file
rsadata_list = []
c = None
e = None
N = None
f = open("hastadlist.txt", 'r')
for line in f:
	if line.startswith("e"):
		e = long(line.split(" ")[2])
	elif line.startswith("n"):
		N = long(line.split(" ")[2], 0)
	elif line.startswith("ciphertext"):
		c = long(line.split(" ")[2], 0)
		rsadata_list.append(RSAData(rsa_obj(N, e), TextData(c, 1)))
f.close()

# Library specific call
# Run the exploit by specifying it
if Hastad().run(rsadata_list):		
    print num2string(rsadata_list[0].get_m())
```


####CTF Problem: Hack.lu 2014 - Wiener:
It’s gold rush time! The New York Herald just reported about the Californian gold rush. We know a sheriff there is hiring guys to help him fill his own pockets. We know he already has a dreadful amount of gold in his secret vault. However, it is protected by a secret only he knows. When new deputies apply for the job, they get their own secret, but that only provies entry to a vault of all deputy sheriffs. No idiot would store their stuff in this vault. But maybe we can find a way to gain access to the sheriff’s vault? Have a go at it:
nc wildwildweb.fluxfingers.net 1426

Analysis of server RSA implementation:
* Public key is accessible through server
* The size of the private exponent(d) in bits is around 1/5 of the modulus

The name of the problem gives it away, but this cryptosystem is vulnerable to Wiener's Attack. Wiener's attack is able to recover the private exponent d when d < N^(1/4). Once again, our library could be used to reduce the amount of time needed to write a script that uses Wiener's attack to recover the private key and decrypt the message. The script that the user has to write might resemble the following:

```
from RSAExploits import rsa_cracker
from RSAExploits import RSAData
from RSAExploits import rsa_obj
from RSAExploits import TextData
from RSAExploits import num2string
from RSAExploits import Wiener
import sys

sys.setrecursionlimit(10000)

# Parse and store all of the ciphertexts provided by the file
rsadata_list = []
rsadata_list.append(RSAData(rsa_obj(n, e)))       # Assume n and e have been initialized
if Wiener().run(rsadata_list):		
    print (rsadata_list[0].get_d())
```


####CTF Problem: PicoCTF 2014 - RSA Mistakes:
Daedalus Corp seems to have had a very weird way of broadcasting some secret data. We managed to find the server code that broadcasted it, and one of our routers caught some of their traffic - can you find the secret data? We think someone may have requested the secret using someone else's user id by accident, but we're not sure. 

Analysis of server RSA implementation and capture file:
* All messages are encrypted using a public exponent of 3
* Two messages have been encrypted using the same public key (N,e)
* Those 2 messages are related by a known polynomial

This problem is vulnerable to the Franklin-Reiter Related Message attack. When two messages differ by a known amount and are encrypted using the same public key, then we compute the message directly. However, the Franklin-Reiter attack will only terminate in a reasonable amount of time if the public exponent e is small. Lucky for us, that is the case. So, a user of our library should only have to provide the modulus, public exponent, two ciphertexts, and a polynomial representing the relationship of the two plaintext messages used to generate the ciphertexts. The rest of the work would be taken care of by the pre-implemented Franklin-Reiter exploit. The resulting script might resemble the following:

```
from sage.all_cmdline import *
from RSAExploits import rsa_cracker
from RSAExploits import RSAData
from RSAExploits import rsa_obj
from RSAExploits import TextData
from RSAExploits import num2string
from RSAExploits import mod_inv
from RSAExploits import Franklin_Reiter
import sys

sys.setrecursionlimit(10000)

# Assume N, e, c1, c2, a, and b have been initialized

info_dict = {}
rsadata_list = []
rsadata_list.append(RSAData(rsa_obj(long(N), long(e)), TextData(c1)))
rsadata_list.append(RSAData(rsa_obj(long(N), long(e)), TextData(c2)))

x = PolynomialRing(ZZ.quo(N*ZZ), 'x').gen()
poly = a*x + b
info_dict["Franklin_Reiter"] = poly

# Run exploit
if Franklin_Reiter().run(rsadata_list, info_dict):
    plaintext = rsadata_list[0].get_m()
    print num2string(plaintext)

```

The actual full script that solves RSA Mistakes would be a little more involved. The plaintext messages are transformed before they are encrypted resulting in a few more steps at the end.


### Future Work
There are still many RSA exploits that have yet to be implemented/added to our library. Among these are Coppersmith's Short Pad attack, Partial Key Exposure attacks, and Hastad's generalized broadcast attack. Future work could involve implementing these new exploits, improving code quality of the library, improving code efficiency, and improving usability.
