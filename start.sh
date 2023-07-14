#!/bin/bash

if [ -z "$1" ]; then
  echo "Please provide the path to the .ini file."
  exit 1
fi

config_file="$1"
nohup sudo python3 -m TheSapiPot "$config_file" > /dev/null 2>&1 &

# Generate stop_script.sh
echo "#!/bin/bash" > stop_script.sh
echo "" >> stop_script.sh
echo "pkill -f \"python3 -m TheSapiPot $config_file\"" >> stop_script.sh
chmod +x stop_script.sh
