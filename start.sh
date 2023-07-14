#!/bin/bash

if [ -z "$1" ]; then
  echo "Please provide the path to the .ini file."
  exit 1
fi

config_file="$1"
nohup sudo python3 -m TheSapiPot "$config_file" > /dev/null 2>&1 &

# Generate stop.sh
echo "#!/bin/bash" > stop.sh
echo "" >> stop.sh
echo "pkill -f \"python3 -m TheSapiPot $config_file\"" >> stop.sh
chmod +x stop.sh
