# W3brute - Automatic Web Application Brute Force Attack Tool 

[![Build Status](https://travis-ci.com/aprilahijriyan/w3brute.svg?branch=master)](https://travis-ci.com/aprilahijriyan/w3brute) [![Python 2.6|2.7](https://img.shields.io/badge/python-2.6|2.7-yellow.svg)](https://www.python.org/downloads/) [![License](https://img.shields.io/badge/license-LGPLv3-green.svg)](https://raw.githubusercontent.com/aprilahijriyan/w3brute/master/LICENSE)

w3brute is an open source penetration testing tool that automates attacks directly to the website's login page. w3brute is also supported for carrying out brute force attacks on all websites.

Features
--------

1. Scanner:

   w3brute has a scanner feature that serves to support the **bruteforce attack** process.
   
   this is a list of available scanners:

   * automatically detects target authentication type.
   * admin page scanner.
   * SQL injection scanner vulnerability.

2. Attack Method:

   w3brute can attack using various methods of attack.
   
   this is a list of available attack methods:

   * SQL injection bypass authentication
   * mixed credentials (username + SQL injection queries)

3. Support:

   * multiple target
   * google dorking
   * a list of supported web interface types to attack:
      + **web shell**
      + **HTTP 401 UNAUTHORIZED** (*Basic* and *Digest*)

   * create file results **brute force** attack. supported file format type: 
      + **CSV** (default)
      + **HTML**
      + **SQLITE3**

   * custom credentials (username, password, domain) (supported **zip** file) 
   * custom HTTP requests (User-Agent, timeout, etc)
   * and much more...


Screenshot
----------

![image](https://github.com/aprilahijriyan/w3brute/blob/master/screenshot.jpg)


Installation
------------

You can download the latest version of the tarball file [here](https://github.com/aprilahijriyan/w3brute/tarball/master) or zipball [here](https://github.com/aprilahijriyan/w3brute/zipball/master).

If you have installed the `git` package, you can clone the [Git repository](https://github.com/aprilahijriyan/w3brute) in a way, as below: 

    git clone https://github.com/aprilahijriyan/w3brute.git

w3brute can be run with [Python](https://www.python.org/downloads/) version __2.6.x__ or __2.7.x__ on all platforms.


Usage
-----

To get all list of options on w3brute tool:

    python w3brute.py -h

Examples:

```bash

# basic usage
$ python w3brute.py -t http://www.example.com/admin/login.php

# look for the admin page
$ python w3brute.py -t http://www.example.com/ --admin

# uses a password file zip list. (syntax => <path><;filename>[:password])
$ python w3brute.py -t http://www.example.com/ --admin -u admin -p /path/to/file.zip;filename.txt # (if the file is encrypted: /path/to/file.zip;filename.txt:password)

# slice the password from the list. (syntax => <start>[:stop][:step])
$ python w3brute.py -t http://www.example.com/ --admin -u admin -sP 20000

```

Disclaimer
----------

Usage of w3brute for attacking targets without prior mutual consent is illegal. 
It is the end user's responsibility to obey all applicable local, state and federal laws. 
Developers assume NO liability and are NOT responsible for any misuse or damage caused by this program.


Contribute
----------

see the [CONTIRBUTING.md](https://github.com/aprilahijriyan/w3brute/blob/master/doc/CONTRIBUTING.md) file.


Donate
------

Process of making w3brute costs a lot of time, thought, energy and of course also consumes a lot of food and coffee, and also internet connection! xD

If you support me and want to see a growing w3brute, of course you need to donate a little money to me, as a sign that you appreciate this project.

You can send your money via PayPal to: **donate.w3brute@gmail.com**


Links
-----

* Download: [.tar.gz](https://github.com/aprilahijriyan/w3brute/tarball/master) or [.zip](https://github.com/aprilahijriyan/w3brute/zipball/master)
* Issue tracker: https://github.com/aprilahijriyan/w3brute/issues
* Youtube: https://youtu.be/u4mi-cfRfGA
