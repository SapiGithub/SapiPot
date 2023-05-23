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
      ports= 8888,9999,2321
      logfile=sapiPot.log
"""

import docopt
import configparser
import sys
from TheSapiPot import HoneyPot

if len(sys.argv) < 2 or sys.argv[1] in ['-h','--help']:
  print(__doc__)
  sys.exit(1)
config_filepath = sys.argv[1]
config = configparser.ConfigParser()
config.read(config_filepath)
host = config.get("default",'host',raw=True,fallback='0.0.0.0')
interface = config.get("default",'interface',raw=True)
ports = config.get("default",'ports',raw=True,fallback='22,80,443,8080,8888,9999,3306')
logfile = config.get("default",'logfile', raw=True,fallback='/var/log/sapipot.log')

ports_list = []
try:
    ports_list = ports.split(',')
except Exception as e:
    print('[-] Err listing port: ', ports)
    sys.exit()
    
honeyPot = HoneyPot(host,interface,ports_list,logfile)
honeyPot.run()