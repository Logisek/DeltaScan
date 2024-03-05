# DeltaScan
DeltaScan is a sophisticated network scanning tool designed to detect and report changes in open ports and services over time. By conducting scheduled scans and providing differential analysis, it offers invaluable insights for proactive cybersecurity management and breach prevention.

### Installation
Install `pipenv`:
```bash
pip install pipenv # globally
or
pip install pipenv --user # for current user
```

Install the DeltaScan:
```bash
cd DeltaScan
pipenv install -e .
```

Run for development:
```bash
pipenv run python main.py
```

Install globally as executable:
```bash
python3 setup.py
```

Without using pipenv:
```bash
python3 -m venv venv
source venv/bin/activate
python setup.py install
```

Using both `Pipenv` and `setup.py` let's develop on a solid environment that is dpendency compatibility safe (due to Pipfile.locl) but also, potentially, distribute the application and let users install it with setup.py. 