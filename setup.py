from setuptools import setup, find_packages

setup(
    name='DeltaScan',
    version='1.0.0-alpha',
    description='A package for scanning deltas',
    author='logisek',
    url='https://github.com/Logisek/DeltaScan',
    packages=find_packages(),
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
        "wcwidth==0.2.12"
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU GENERAL PUBLIC LICENSE',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    entry_points={ 'console_scripts': [ 'deltascan = deltascan:main' ] },
)