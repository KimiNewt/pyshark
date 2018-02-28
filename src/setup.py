import os
from setuptools import setup, find_packages

with open(os.path.join(os.path.dirname(__file__), 'README.txt')) as f:
    long_description = f.read()

setup(
    name="py3shark",
    version="0.4.0",
    packages=find_packages(),
    package_data={'': ['*.ini', '*.pcapng']},
    install_requires=['lxml', 'py', 'logbook'],
    tests_require=['mock', 'pytest'],
    url="https://github.com/laixintao/py3shark",
    long_description=long_description,
    author="KimiNewt",
    description="Python wrapper for tshark, a fork for pyshark support Python3.5+",
    keywords="wireshark capture packets parsing packet",

    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.5',
    ],
)
