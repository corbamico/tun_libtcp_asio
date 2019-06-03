# Readme

Demostrate c++ example tun operation and tcp handshake on tun channel by studying following stream.

code based on following lecture:  
youtube <https://www.youtube.com/watch?v=bzja9fQWzdA>  
code <https://github.com/jonhoo/rust-tcp>  

see same lab rust project [here](https://github.com/corbamico/tun_rx_libtcp)

## Dependencies

* [libviface](https://github.com/HPENetworking/libviface)

  ```shell
  make && make install
  ```  
  if libviface.so.1.1.0 cannot loaded, copy it to LD_LIBRARY_PATH

* asio (standalone mode) and libtins

  ```shell
  sudo apt-get install libasio-dev libtins-dev
  ```

## laboratory

### lab1

* description  
  Hump hex stream, which received from tun.

  ```shell
  mkdir build && cd build && cmake .. && make
  #run lab1 as 
  bin/lab1/lab1
  #open another shell to send tcp package
  nc -s 10.0.0.1 10.0.0.5 8000
  ```

### lab2

* description  
  icmp ping ack server, which received from tun.

### lab3

* description  
  icmp ping ack server, re-factory lab2, using separate read/write buffer.

### lab4

* description  
  simple tcp server, handle syn/psh/fin tcp connection, and print tcp payload on std::cout.

### lab5

* description  
  simple tcp server/session, handle all tcp status transaction of server side via using boost::sml state_machine

### lab6

* description  
  - [x] simple tcp server/session,  
  - [x] allow multiply clients,  
  - [x] handle all tcp status transaction of server side via using boost::sml state_machine,
  - [x] max sessions, and timeout at synrcvd to simple avoid syn-flood,  

iperf througput test in container (docker in windows 10) as:

```shell
/h/c/tun_libtcp_asio# iperf -c 10.0.0.100 -t 5 -p 8000 -i 1        
------------------------------------------------------------                         
Client connecting to 10.0.0.100, TCP port 8000                                       
TCP window size: 45.0 KByte (default)                                                
------------------------------------------------------------                         
[  3] local 10.0.0.1 port 46526 connected with 10.0.0.100 port 8000                  
[ ID] Interval       Transfer     Bandwidth                                          
[  3]  0.0- 1.0 sec  37.5 MBytes   315 Mbits/sec                                     
[  3]  1.0- 2.0 sec  36.9 MBytes   309 Mbits/sec                                     
[  3]  2.0- 3.0 sec  37.6 MBytes   316 Mbits/sec                                     
[  3]  3.0- 4.0 sec  37.6 MBytes   316 Mbits/sec                                     
[  3]  4.0- 5.0 sec  36.9 MBytes   309 Mbits/sec                                     
[  3]  0.0- 5.0 sec   186 MBytes   313 Mbits/sec                                     
```

## Reference

### IP Header V4

![ip header](doc/images/IP-Header-v4.png "IPv4 Header")

### ICMP Header

![icmp header](doc/images/ICMP-Header.png "ICMP Header")

## License

>Copyright (C) 2019 corbamico
>
>Licensed under the Apache License, Version 2.0 (the "License");  
>you may not use this file except in compliance with the License.  
>You may obtain a copy of the License at  
>
>http://www.apache.org/licenses/LICENSE-2.0  
>
>Unless required by applicable law or agreed to in writing,  
>software distributed under the License is distributed on an  
>"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY  
>KIND, either express or implied.  See the License for the  
>specific language governing permissions and limitations  
>under the License.  