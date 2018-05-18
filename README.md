```  
 _____           _   _____                       _
/  __ \         | | /  __ \                     | |
| /  \/ ___ _ __| |_| /  \/_ __ _   _ _ __   ___| |__  _   _
| |    / _ \ '__| __| |   | '__| | | | '_ \ / __| '_ \| | | |
| \__/\  __/ |  | |_| \__/\ |  | |_| | | | | (__| | | | |_| |
 \____/\___|_|   \__|\____/_|   \__,_|_| |_|\___|_| |_|\__, |
                                                        __/ |
                                                       |___/
Just a silly recon tool that uses data from SSL Certificates to find potential hostnames
```

## What the?
It just a silly python script that either retrieves SSL Certificate based data from online sources,
currently https://crt.sh/ and https://censys.io. 
If you want to use Censys.io you need to register for a API key.

## How to use it? 
Very simply
-d to get hostnames for spesific domain 

-D to get hostnames for a list of domains (just stuff it in a line delimeted text file)  

-U censys.io UID (If you have one) 

-S censys.io Secret (If you have one) 


for the rest, im still working on those :)

## Todo:
1. Better documentation
2. Add the code to extract and parse x509 certs from ip ranges
3. Better output
