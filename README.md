# Toy-Pot

This is a toy SSH Honeypot made using Paramiko Module in Pyhton.
The Honeypot generates sample terminal text which can be used to befool the hacker.
It is a toy baiting system which can be extended to actual honeypot using a vulnerable machine.

## Some Key Points related to the Project

o Connections are made using Paramiko in python.

o The default port on which the Honeypot runs is 2222 instead of 22.
Reason is quite obvious that we dont want to make our machine's actual SSH port 22 vulnerable.

## Documentation

[Paramiko](https://www.paramiko.org/)

## Installation

Installation `Toy-Pot`

Route SSH port to 2222 for safety

```
  iptables -A PREROUTING -t nat -p tcp --dport 22 -j REDIRECT --to-port 2222
```

Requirment

```
  ssh-keygen -t rsa -f server.key
```

Run

```
  pip3 install --upgrade pip
  pip3 install -r paramiko
```

On the Attackers side Use any testing tool of Backtrack(Kali Linux)

[n-map](https://nmap.org/)
