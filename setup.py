from setuptools import setup, find_packages

setup(
    name='deltascan',
    version='0.0.1',
    description='A package for scanning deltas',
    author='logisek',
    url='https://github.com/Logisek/DeltaScan',
    python_requires='>3.8',
    install_requires=[
        "blessed==1.20.0",
        "chardet==5.2.0",
        "inquirer==3.1.4",
        "markdown-it-py==3.0.0",
        "mdurl==0.1.2",
        "peewee==3.17.0",
        "Pillow==10.1.0",
        "Pygments==2.17.2",
        "python-editor==1.0.4",
        "python3-nmap==1.6.0",
        "readchar==4.0.5",
        "reportlab==4.0.8",
        "rich==13.7.0",
        "simplejson==3.19.2",
        "six==1.16.0",
        "wcwidth==0.2.12",
        "pyyaml==6.0",
        "python3-nmap==1.6.0",
        "marshmallow==3.14.0",
        "python-libnmap==0.7.3",
        "jinja2==3.1.3",
        "pdfkit"
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.1",
            "black>=21.12b0",
            "dotmap"
        ]
    },
    packages=find_packages(exclude=['tests']),
    entry_points={
        'console_scripts': ['deltascan = deltascan.cli.cmd:run']
    },
)
