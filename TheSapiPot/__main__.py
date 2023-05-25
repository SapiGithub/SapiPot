"""
SapiPot.

Usage:
  python3 -m TheSapiPot <config_filepath>

Options:
  -h, --help             Show this screen.
  <config_filepath>     Path to config option .ini file

  .ini file value:
      [default]
      host = 0.0.0.0 
      interface = wlan0
      logfile=sapiPot.log
"""

import configparser
import sys
from scapy.all import conf,get_if_addr
from TheSapiPot import HoneyPot

if len(sys.argv) < 2 or sys.argv[1] in ['-h','--help']:
  print(__doc__)
  sys.exit(1)
config_filepath = sys.argv[1]
config = configparser.ConfigParser()
config.read(config_filepath)
host = config.get("default",'host',raw=True,fallback=get_if_addr(conf.iface))
interface = config.get("default",'interface',raw=True,fallback=conf.iface)
logfile = config.get("default",'logfile', raw=True,fallback='/var/log/sapipot.log')
  
honeyPot = HoneyPot(host,interface,logfile)
honeyPot.run()
