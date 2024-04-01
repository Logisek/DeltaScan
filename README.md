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
pipenv install -d -e .
```

Run for development:
```bash
pipenv run python main.py
```
For generating pdf reports we use pdfkit library. In order for it to work you need to install
wkhtmltopdf.

Debian
```
sudo apt-get install wkhtmltopdf
```
For Windows, downlaod (wjhtmltopdf.exe)[https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/wkhtmltox-0.12.4_msvc2015-win64.exe] library and add it to your PATH.

#### TODO:
- Verbose mode fix
- Review cli interface