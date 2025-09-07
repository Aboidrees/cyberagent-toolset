---
id: <unique-id>
title: <human title>
vars:
  target: "example.com"
steps:
  - name: <step name>
    uses: dns.resolve|whois.lookup|nmap.scan|http.headers|http.get|tls.inspect|subdomains.passive
    with: { ... executor-specific options ... }
...
# Notes

Any free-form notes or documentation can be added here. Use YAML front-matter to define variables and steps.