# DeltaScan
DeltaScan is a sophisticated network scanning tool designed to detect and report changes in open ports and services over time. By conducting scheduled scans and providing differential analysis, it offers invaluable insights for proactive cybersecurity management and breach prevention.

### Installation
Install `pipenv`:
```bash
pip install pipenv # globally
# or
pip install pipenv --user # for current user
```

Install for development:
```bash
cd DeltaScan
pipenv install -d -e .
```

Install and run the help command first of all:
```bash
pipenv install -e .
pipenv run deltascan --help
```
Because the nmap requires sudo for many of its actions we also have to run deltascan with sudo. The problem is that as long as you run a program with sudo, none of your environmental variables exist anymore. This is why we have to persist out env variables (mostly it's about PYTHONPATH)
```bash
sudo -E env PATH=${PATH} pipenv run deltascan <command & arguments>
```
In the above command sudo flag '-E' persists the current env variables.

Of course you can always run it without pipenv:
```bash
python3 main.py <command & arguments>
# or
sudo python3 main.py <command & arguments>
```

For generating pdf reports we use pdfkit library. In order for it to work you need to install
wkhtmltopdf.

Debian
```bash
sudo apt-get install wkhtmltopdf
```
For Windows, downlaod (wjhtmltopdf.exe)[https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/wkhtmltox-0.12.4_msvc2015-win64.exe] library and add it to your PATH.

If you wish to install deltascan as a cli tool you can run:
```bash
# Global installation
sudo pip install .
deltascan --help
# and for use with sudo
sudo deltascan <your command & arguments>

# For installation within a virtual environment
python3 -m venv venv
pip install .
deltascan --help
sudo -E env PATH=${PATH} deltascan <command & arguments>
```

### Tests
Run tests
```bash
pipenv run pytest
```

### Examples

Scan:
```bash
sudo -E env PATH=${PATH} pipenv run deltascan -a scan -c config.yaml -p MY_PROFILE -t 192.168.0.100
sudo -E env PATH=${PATH} pipenv run deltascan -a scan -c config.yaml -p MY_PROFILE -t 192.168.0.100/24
sudo -E env PATH=${PATH} pipenv run deltascan -a scan -c config.yaml -p MY_PROFILE -t 192.168.0.100 -o export.<csv|pdf|html>

# The -s bool flag exports each scan in a separate file
sudo -E env PATH=${PATH} pipenv run deltascan -a scan -c config.yaml -p MY_PROFILE -t 192.168.0.100 -s

# The below command uses a custom template file (it has to be an .html file)
sudo -E env PATH=${PATH} pipenv run deltascan -a scan -c config.yaml -p MY_PROFILE -t 192.168.0.100 --template your_template.html
```

Compare:
```bash
pipenv run deltascan -a compare -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" -t 192.168.0.100
pipenv run deltascan -a compare -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" -t 192.168.0.100/24
pipenv run deltascan -a compare -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" -t 192.168.0.100/24 -o export.<csv|pdf|html>

# The "--n-scans 20 --n-diffs -2" means "from below command mean from the last 20 scans show the latest differences"
pipenv run deltascan -a compare -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" --n-scans 20 --n-diffs -2 -t 192.168.0.100

# The below command uses a custom template file (it has to be an .html file)
pipenv run deltascan -a compare -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" --n-scans 20 --n-diffs -2 -t 192.168.0.100 --template your_template.html
```

View:
```bash
pipenv run deltascan -a view -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" -t 192.168.0.100
pipenv run deltascan -a view -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" -t 192.168.0.100/24
pipenv run deltascan -a view -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" -t 192.168.0.100/24 -o export.<csv|pdf|html>

# The below command brings only the open ports from the defined scans
pipenv run deltascan -a view -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" --port-type open -t 192.168.0.100

```

Import:
```bash
pipenv run deltascan -a import -i previous_exports.csv
pipenv run deltascan -a import -i raw_nmap_results.xml
```

### Documentation
Run mkdocs server:
```bash
pipenv run mkdocs serve
```
