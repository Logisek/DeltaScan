     _____        _
    (____ \      | |_                             
     _   \ \ ____| | |_  ____  ___  ____ ____ ____  
    | |   | / _  ) |  _)/ _  |/___)/ ___) _  |  _ \ 
    | |__/ ( (/ /| | |_( ( | |___ ( (__( ( | | | | |
    |_____/ \____)_|\___)_||_(___/ \____)_||_|_| |_|    

DeltaScan is an advanced port scanning tool designed to detect and report changes in open ports and services over time. It offers scan results manipulation functionalities like export, import, differential check between scans and an interactive shell. 
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
# execute commands 
sudo -E env PATH=${PATH} pipenv run deltascan <command & arguments>
```

Standalone installation:
```bash
python3 main.py <command & arguments>
# or
sudo python3 main.py <command & arguments>
```

For generating pdf reports we use pdfkit library. In order for it to work you need to install
wkhtmltopdf.

For Linux:
```bash
sudo apt-get install wkhtmltopdf
```
For Windows, downlaod (wjhtmltopdf.exe)[https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/0.12.4/wkhtmltox-0.12.4_msvc2015-win64.exe] library and add it to your PATH.

If you wish to install deltascan as a cli standalone tool you can run:
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

### <b>IMPORTANT</b>: 
#### `example_dscan_results_for_html_template.json` is the schema of the dict that is stored in the database and exposed to be used inside your custom html template (see core/templates). Hence, these are the Nmap fields that are stored at the moment. More Nmap results are going to be added in future releases.


### Tests
Run tests
```bash
pipenv run pytest
```

### Functionality

###### config.yaml
The configuration file contains a list of profiles (profile name and its arguments). Users can add new profiles in the `config.yaml`.
```yaml
profiles:
    TCP_PORTS_TOP_1000_NO_PING_NO_DNS:
        arguments: "-sS -n -Pn -vv --top-ports 1000 --reason --open"
    TCP_PORTS_FULL_NO_PING_NO_DNS: 
        arguments: "-sS -n -Pn -vv -p- --reason --open"
    UDP_PORTS_TOP_1000_NO_PING_NO_DNS:
        arguments: "-sU -n -Pn -vv --top-ports 1000 --reason --open"
```
##### Scan:
Scan hosts or subnets like nmap. Flag `-p` is the profile selection, where you can select a profile available from the given `-c config.yaml` or existing in the database. A given profile, given in the config file, is stored in the database and then used from there.
Scanning uses a target host, a configuration file, and a profile.
```bash
sudo -E env PATH=${PATH} deltascan scan -c config.yaml -p MY_PROFILE -t 192.168.0.100
sudo -E env PATH=${PATH} deltascan scan -c config.yaml -p MY_PROFILE -t 192.168.0.100/24
sudo -E env PATH=${PATH} deltascan scan -c config.yaml -p MY_PROFILE -t 192.168.0.100 -o export.<csv|pdf|html>

# The -s bool flag exports each scan in a separate file
sudo -E env PATH=${PATH} deltascan scan -c config.yaml -p MY_PROFILE -t 192.168.0.100 -s

# The below command uses a custom template file (it has to be an .html file)
sudo -E env PATH=${PATH} deltascan scan -c config.yaml -p MY_PROFILE -t 192.168.0.100 --template your_template.html
```

##### Diffs:
Listing the differences between scans is the next key feature. By providing a host and a profile, you can list all the differences that have occurred for the specific host and profile in the given time period specified by `--from-date` and `--to-date`. The scan comparison happens between every consecutive scan pair and is added to the diff list only if at least one added, changed, or removed key is found. 

```bash
sudo -E env PATH=${PATH} deltascan diff -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" -t 192.168.0.100
sudo -E env PATH=${PATH} deltascan diff -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" -t 192.168.0.100/24
sudo -E env PATH=${PATH} deltascan diff -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" -t 192.168.0.100/24 -o export.<csv|pdf|html>

# The "--n-scans 20 --n-diffs -2" means "from below command mean from the last 20 scans show the latest differences"
sudo -E env PATH=${PATH} deltascan diff -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" --n-scans 20 --n-diffs -2 -t 192.168.0.100

# The below command uses a custom template file (it has to be an .html file)
sudo -E env PATH=${PATH} deltascan diff -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" --n-scans 20 --n-diffs -2 -t 192.168.0.100 --template your_template.html
```

##### View:
Listing scan results is a simple query to the deltascan database. The query takes into account the given parameters (`host`, `profile`, `--from-date`, `--to-date`, `--port-type`)
```bash
sudo -E env PATH=${PATH} deltascan view -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" -t 192.168.0.100
sudo -E env PATH=${PATH} deltascan view -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" -t 192.168.0.100/24
sudo -E env PATH=${PATH} deltascan view -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" -t 192.168.0.100/24 -o export.<csv|pdf|html>

# The below command brings only the open ports from the defined scans
sudo -E env PATH=${PATH} deltascan view -c config.yaml -p MY_PROFILE --from-date "2024-01-01 10:00:00" --to-date "2024-01-02 10:00:00" --port-type open -t 192.168.0.100

```

##### Import:
Importing nmap, raw, scan results.
```bash
sudo -E env PATH=${PATH} deltascan import -i raw_nmap_results.xml
```
Importing DeltaScan results from `.csv` file (probably from another DeltaScan database).
```bash
sudo -E env PATH=${PATH} deltascan import -i previous_exports.csv
```

##### Export/Report:
Exporting the results of the operation requires just the flag `-o` or `--output` with a file name and an extension of `pdf`, `html` or `csv`. The `csv` results are the only output format (at the moment) that exports the whole, raw scan results and can be used to import the scans in another DeltaScan database.

`html`: Html reports are generated from the given template. The default templates are in `deltascan/core/templates`. There are two different template types, one for scan results and one for diff results. Custom templates can be provided using the flag `--template <name_of_template_file>`. The fields that DeltaScan exposes to be used inside the custom template, are shown in `example_dscan_results_for_html_template.json` for scan results and `example_diff_results_for_html_templayte.json` for diff results.

`pdf`: Pdf reports are actually the html report converted to `pdf`, so html details are also applied here.

`csv`: Csv reports are actually database dumps. Database fields are exported as they are. The main use of a csv export is to use it as an import file to another DeltaScan database or (using a custom parser) to load it to another tool/application.

##### Interactive shell options:

```bash
deltascan>: ?                                # Display help
    Documented commands (type help <topic>):
    ========================================
    clear  diff        exit  imp       q     report  view
    conf   diff_files  help  profiles  quit  scan
    Interactive shell:
deltascan>: conf                             # Display current configuration
    output_file:         out_file.html
    template_file:       None
    import_file:         None
    diff_files:          None
    n_scans:             1
    n_diffs:             1
    From date [fdate]:   None
    To date [tdate]:     None
    suppress:            False
    host:                0.0.0.0
    profile:             None
deltascan>: conf suppress=true              # Modify configuration value
deltascan>: view                            # View result based on current configuration parameters
    # ... Results ...
deltascan>: diff 1,2                        # Difference between previous view results (always use suppress=True to find diff indexes)
deltascan>: imp nmap_dump_file.0.0.0.0.xml  # Import nmap dump file
deltascan>: imp nmap_dump_file.0.0.0.0.csv  # Import deltascan csv exported file
deltascan>: report                          # Report last results (must set an output_file before with: conf output_file=filename.(html|pdf|csv))
deltascan>: diff_files d1.xml,d2.xml        # Differences between two nmap dump files
deltascan>: profiles                        # List profiles in database
deltascan>: scan 0.0.0.0 PROFILE            # Scan with IP and profile
```

### Documentation
Run mkdocs server:
```bash
pipenv run mkdocs serve
```
