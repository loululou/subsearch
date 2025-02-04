# How to use
  
Prepare subdomain list
```
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt -O subdomains.txt
```

Start to search
```
python3 subsearch.py DOMAIN
```

---

If you get:  
ImportError: No module named dns  

You can install dns python
```
sudo apt-get install python3-dnspython
```
