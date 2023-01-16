# traceroute
Minimalistic traceroute written in rust for learning purposes.

## Usage
To run the programm you need the root priviliges.
```bash
cargo run --bin tracert <ip> <max_ttl> <timeout>
```
Example: 

```
cargo run --bin tracert ya.ru 30 2
trace route to 87.250.250.242 (ya.ru)
1 192.168.0.1 4.633ms 1.438ms 1.391ms 
2 92.42.26.1 (vlan814.pi.bb.pu.ru) 3.812ms 3.103ms 3.336ms 
3 172.24.31.5 3.405ms 4.395ms 1.522ms 
4 172.24.25.32 (vunk-punk.rtr.pu.ru) 3.875ms 2.543ms 2.396ms 
5 172.24.25.38 (magma-vunk.rtr.pu.ru) 24.121ms 28.143ms 32.426ms 
6 195.70.196.3 (vlan3.kronos.pu.ru) 5.839ms 3.098ms 2.602ms 
7 195.70.206.129 5.139ms 2.723ms 2.561ms 
8 185.1.152.57 (yandex.spb.piter-ix.net) 4.948ms 3.373ms 3.261ms 
9 93.158.160.151 (vla-32z1-ae3.yndx.net) 16.754ms 14.040ms 14.187ms 
10 * * * 
11 87.250.250.242 (ya.ru) 20.798ms 14.247ms 14.106ms 
```
