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
      dirfile = /home/sapikali/Documents/Thesis/TCPSapiPot/uploaded #full path 
      logfile= /home/sapikali/Documents/Thesis/TCPSapiPot/sapiPot.log #full path 
"""

import configparser
import sys
import os
from scapy.all import conf,get_if_addr
from TheSapiPot import HoneyPot

if len(sys.argv) < 2 or sys.argv[1] in ['-h','--help']:
  print(__doc__)
  sys.exit(1)
config_filepath = sys.argv[1]
config = configparser.ConfigParser()
config.read(config_filepath)
interface = config.get("default",'interface',raw=True,fallback=conf.iface)
host = get_if_addr(interface)
dirfile = config.get("default",'dirfile',raw=True)
csvfile = config.get("default",'csvfile', raw=True)
if(dirfile == ""):
  desktop_path = os.path.expanduser("~/Desktop")
  folder_path = os.path.join(desktop_path, "SapiDirFile")
  if not os.path.exists(folder_path):
    os.makedirs(folder_path)
  dirfile=folder_path
if(csvfile == ""):
  desktop_path = os.path.expanduser("~/Desktop")
  log_path = os.path.join(desktop_path, "SapiPot.csv")
  if not os.path.exists(log_path):
    open(log_path, 'a').close()
  csvfile=log_path
honeyPot = HoneyPot(host,interface,dirfile,csvfile)
honeyPot.run()
