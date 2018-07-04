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
currently https://crt.sh/, https://certdb.com/, https://sslmate.com/certspotter/ and https://censys.io or given a IP range it will attempt to extract host information from SSL Certificates.
If you want to use Censys.io you need to register for a API key.

## Demo
![gif](https://i.imgur.com/fsZFflZ.gif)

## How to install
```
git clone https://github.com/joda32/CertCrunchy.git
cd CertCrunchy
sudo pip3 install -r requirements.txt
```

## How to use it?
Very simply
-d to get hostnames for specific domain

-D to get hostnames for a list of domains (just stuff it in a line delimited text file)  

-i to retrieve and parse certificates from hosts in a netblock / ip range (e.g. 192.168.0.0/24) 

-T the thread count, makes stuff faster, but don't over do it

-o Output file name

-f Output format csv or json, csv is the default

for the rest, I'm still working on those :)

## API keys and configs
All API keys are stored in the api_keys.py file, below is a list of supported APIs requiring API keys.

1. Censys.oi https://censys.io

## Todo:
1. Better documentation
