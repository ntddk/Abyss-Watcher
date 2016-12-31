#!/usr/bin/env python
# coding: UTF-8

from __future__ import print_function
from datetime import datetime
from bs4 import BeautifulSoup
import socket
import socks
import hashlib
import magic
import os
import argparse
import sys
import threading
import logging
from logging import getLogger, StreamHandler, DEBUG

def fetch_soup(name, url):
    request = urllib2.Request(url)
    request.add_header('User-Agent', 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)')

    try:
        html = urllib2.urlopen(request, timeout=10)

    except urllib2.URLError as e:
        logger.error('{0}: {1}, fetching from {2}'.format(name, e.reason, url))
        return

    except Exception as e:
        logger.error('{0}: Failed to fetch from {1}'.format(name, url))
        return

    soup = BeautifulSoup(html, 'html.parser')
    return soup

def fetch_file(name, url, dest_path):
    try:
        file_binary = urllib2.urlopen(url, timeout=10).read()

    except urllib2.URLError as e:
        logger.error('{0}: {1}, fetching from {2}'.format(name, e.reason, url))
        return

    except Exception as e:
        logger.error('{0}: Failed to fetch from {1}'.format(name, url))
        return

    filetype = magic.from_buffer(file_binary, mime=True).decode(sys.stdin.encoding).split(' ')[0]
    file_md5 = hashlib.md5(file_binary).hexdigest()

    dest_filetype_path = os.path.join(dest_path, filetype)
    dest_file_path = os.path.join(dest_filetype_path, str(file_md5))

    if not os.path.exists(dest_filetype_path):
        os.makedirs(dest_filetype_path)

    if not os.path.exists(dest_file_path):
        with open(dest_file_path, 'wb') as f:
            f.write(file_binary)
        logger.debug('{0}: Saved file type {1} with md5: {2}'.format(name, filetype, file_md5))

def malwaredl(soup, dest_path):
    name = sys._getframe().f_code.co_name
    logger.debug('{0}: Fetching from Malware Domain List'.format(name))
    description_soup = soup('description')[1:]

    logger.debug('{0}: Found {1} urls'.format(name, len(description_soup)))

    for xml in description_soup:
        url = 'http://' + xml.string.replace('&amp;', '&').split(',')[0][6:]
        fetch_file(name, url, dest_path)

def vxvault(soup, dest_path):
    name = sys._getframe().f_code.co_name
    logger.debug('{0}: Fetching from VXvault'.format(name))

    url_list = soup('pre')[0].string.replace('&amp;', '&').split('\r\n')[4:-1]
    logger.debug('{0}: Found {1} urls'.format(name, len(url_list)))

    for url in url_list:
        fetch_file(name, url, dest_path)

def malc0de(soup, dest_path):
    name = sys._getframe().f_code.co_name
    logger.debug('{0}: Fetching from Malc0de'.format(name))

    description_soup = soup('description')[1:]
    logger.debug('{0}: Found {1} urls'.format(name, len(description_soup)))

    for xml in description_soup:
        host = xml.string.replace('&amp;', '&').split(',')[0][5:]
        if host is not None:
            url = 'http://' + host
            fetch_file(name, url, dest_path)
        else:
            ip_address = xml.text.split(',')[1][13:]
            fetch_file(name, 'http://' + ip_address, dest_path)

if __name__ == '__main__':
    print('    ___  _                    _    _       _       _               ')
    print('   / _ \| |                  | |  | |     | |     | |              ')
    print('  / /_\ \ |__  _   _ ___ ___ | |  | | __ _| |_ ___| |__   ___ _ __ ')
    print('  |  _  | `_ \| | | / __/ __|| |/\| |/ _` | __/ __| `_ \ / _ \ `__|')
    print('  | | | | |_) | |_| \__ \__ \\  /\  / (_| | || (__| | | |  __/ |   ')
    print('  \_| |_/_.__/ \__, |___/___/ \/  \/ \__,_|\__\___|_| |_|\___|_|   ')
    print('                __/ |                                              ')
    print('               |___/     v 0.2                                     ')
    print('')

    parser = argparse.ArgumentParser(description='Abyss Watcher - Malware Downloader')
    parser.add_argument('-path', '-p', type=str, help='destination path')
    parser.add_argument('--torify', '-t', action='store_true', help='torify')
    args = parser.parse_args()

    today = datetime.now().strftime('%Y.%m.%d')

    logger = getLogger(today)
    handler = StreamHandler()
    handler.setLevel(DEBUG)
    logger.setLevel(DEBUG)
    logger.addHandler(handler)

    if args.path:
        dest_path = args.path
    else:
        dest_path = today

    if args.torify:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket

    import urllib2

    logger.debug('{0}: {1}'.format(__name__, today))

    try:
        t1 = threading.Thread(target = malwaredl, args = (fetch_soup(__name__, 'http://www.malwaredomainlist.com/hostslist/mdl.xml'), dest_path))
        t2 = threading.Thread(target = vxvault, args = (fetch_soup(__name__, 'http://vxvault.siri-urz.net/URL_List.php'), dest_path))
        t3 = threading.Thread(target = malc0de, args = (fetch_soup(__name__, 'http://malc0de.com/rss'), dest_path))
        t1.start()
        t2.start()
        t3.start()
        t1.join()
        t2.join()
        t3.join()
    except Exception, e:
        logger.error('{0}: {1}'.format(__name__, e))
        pass
