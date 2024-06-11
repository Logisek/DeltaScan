# DeltaScan - Network scanning tool
#     Copyright (C) 2024 Logisek
# 
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>

from setuptools import setup, find_packages


setup(
    name='deltascan',
    version='1.0.0-alpha',
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
        "getkey==0.6",
        "python-libnmap @ git+https://github.com/Logisek/python-libnmap.git@master#egg=libnmap",
        "pdfkit",
        "inputimeout"
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
