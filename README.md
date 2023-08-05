# Honeypot(Linux) for TCP HTTP Payload Detection with TensorFlow for Attack Types

This project focuses on creating a honeypot that specializes in TCP HTTP payload detection using TensorFlow. The honeypot is designed to detect various types of attacks, including Brute Force Attack, Command Injection (Unix), Command Injection (Windows), RFI/LFI, Reverse Shell, SQL Injection, and XSS. It incorporates sentiment analysis to analyze the malicious intent behind the payloads. Additionally, the honeypot includes additional features such as Port Scan Detection (TCP, UDP), ARP Spoof detection, and Folder Monitoring.

## Dependencies
- scapy==2.4.5
- tensorflow==2.12.*
- numpy==1.23.5
- urllib3==1.26.12
- watchdog==3.0.0
- tk==0.1.0

## Installation
1. Clone the repository:

```bash
git clone -b https://github.com/SapiGithub/SapiPot.git
```

2. Navigate to the project directory:

```bash
cd SapiPot
```

3. Install the required dependencies using pip:

```bash
sudo pip3 install -r requirements.txt
```

## Usage
1. Modify the configuration files and settings according to your preferences.

2. Start the honeypot script:

```bash
chmod +x start.sh
sudo ./start.sh <config_filepath>
```

3. The honeypot will start listening for incoming connections on the specified Ip in interface.

4. Monitor the honeypot logs and analyze the detected attacks.
   
5. Stop the honeypot script (auto genereted by start.sh):

```bash
sudo ./stop.sh
```
or close windows GUI

## Configuration
- `TheSapiPot` - Main script for running the honeypot and handling incoming connections.
- `sapipot.ini` - Example forConfiguration file for customizing the honeypot settings.
- `TheSapiPot/model/SentAn` - Directory containing TensorFlow models for sentiment analysis.
- `sapipot.csv` - Example for Log file where honeypot csv are stored.

## Contributing
Contributions are welcome! If you would like to contribute to this project, please follow these steps:

1. Fork the repository.

2. Create a new branch for your feature or bug fix.

3. Make your changes and commit them.

4. Push your changes to your fork.

5. Submit a pull request detailing your changes and their benefits.

## License
This project is licensed under the [MIT License](LICENSE).

## Acknowledgments
- [Scapy](https://scapy.net/) - A powerful interactive packet manipulation program.
- [TensorFlow](https://www.tensorflow.org/) - An open-source machine learning framework.
- [NumPy](https://numpy.org/) - A fundamental package for scientific computing with Python.
- [urllib3](https://urllib3.readthedocs.io/) - A powerful HTTP client for Python.
- [Watchdog](https://pythonhosted.org/watchdog/) - A Python library for monitoring file system events.
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - A really good resources for pyloads
- [Payload Box](https://github.com/payloadbox) - More really good resorces

## Disclaimer
This honeypot is intended for educational and research purposes only. The creators and contributors are not responsible for any misuse or illegal activities conducted with this software.
