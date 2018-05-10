# nmap-hsts
nmap-hsts is a tool that automatically makes requests to web service ports from an Nmap XML results file and reports services that do not set a Strict-Transport-Security header.

## Usage
```
./nmap-hsts.py nmap_results.xml
```