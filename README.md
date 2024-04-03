# DeltaScan
DeltaScan is a sophisticated network scanning tool designed to detect and report changes in open ports and services over time. By conducting scheduled scans and providing differential analysis, it offers invaluable insights for proactive cybersecurity management and breach prevention.

### Installation
Install `pipenv`:
```bash
pip install pipenv # globally
or
pip install pipenv --user # for current user
```

Install for development:
```bash
cd DeltaScan
pipenv install -e .[dev]
```

Install and run the help command first of all:
```bash
pipenv install -e .
pipenv run deltascan --help
```
Because the nmap requires sudo for many of its actions we also have to run deltascan with sudo. The problem is that as long as you run a program with sudo, none of your environmental variables exist anymore. This is why we have to persist out env variables (mostly it's about PYTHONPATH)
```bash
sudo -E pipenv run deltascan <command & arguments>
```
In the above command sudo flag '-E' persists the current env variables.

Of course you can always run it without pipenv:
```bash
python3 main.py <command & arguments>
or
sudo python3 main.py <command & arguments>
```

For generating pdf reports we use pdfkit library. In order for it to work you need to install
wkhtmltopdf.

Debian
```
sudo apt-get install wkhtmltopdf
```
For Windows, downlaod (wjhtmltopdf.exe)[https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/wkhtmltox-0.12.4_msvc2015-win64.exe] library and add it to your PATH.
