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
        "readchar==4.0.5",
        "rich==13.7.0",
        "simplejson==3.19.2",
        "six==1.16.0",
        "wcwidth==0.2.12",
        "pyyaml==6.0",
        "marshmallow==3.14.0",
        "jinja2==3.1.3",
        "python-libnmap @ git+https://github.com/Logisek/python-libnmap.git@develop#egg=libnmap",
        "pdfkit"
    ],
    dependency_links = [''],
    extras_require={
        "dev": [
            "pytest>=7.0.1",
            "black>=21.12b0",
            "dotmap",
            "mkdocs>=1.3.1",
            "mkdocs-material>=8.2.11",
            "mkdocstrings[python]>=0.17.0"
        ]
    },
    packages=find_packages(exclude=['tests']),
    entry_points={
        'console_scripts': ['deltascan = deltascan.cli.cmd:run']
    },
)
