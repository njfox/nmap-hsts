# nmap-hsts
nmap-hsts is a tool that automatically makes requests to web service ports from an Nmap XML results file and reports services that do not set a Strict-Transport-Security header. 

## Usage
```
./nmap-hsts.py nmap_results.xml
```
By default, the tool proxies these requests through http://127.0.0.1:8080 so as to conveniently populate your Burp project with target hosts.