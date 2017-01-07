Abyss Watcher
---
Abyss Watcher is a simple python script that parses malicious url lists from following websites to automatically download the malware sample:

* [Malware Domain List](http://www.malwaredomainlist.com/hostslist/mdl.xml)
* [VX Vault](http://vxvault.siri-urz.net/URL_List.php)
* [Malc0de](http://malc0de.com/rss)

## Installation
```sh
pip install -r requirements.txt
python abyss.py
```

You can specify download location with `-p`.
If you want *[torified](https://www.torproject.org/)* access, following instructions can be used.

```sh
sudo apt-get install tor
sudo service tor start
python abyss.py -t
```

The best way to use Abyss Watcher is to run it routinely from cron--with random delay--like this.

```
0 0 * * * sleep `expr $RANDOM \% 3600`; python /home/ntddk/Abyss-Watcher/abyss.py -t
```

Enjoy!

## Acknowledgments
* [mwcrawler](https://github.com/0day1day/mwcrawler)
* [maruko](https://github.com/tkmru/maruko/)
