import os
from setuptools import setup, find_packages

with open(os.path.join(os.path.dirname(__file__), 'README.txt')) as f:
    long_description = f.read()

setup(
    name="pyshark",
    version="0.6.1",
    packages=find_packages(),
    package_data={'': ['*.ini', '*.pcapng']},
    install_requires=['lxml', 'termcolor', 'packaging', 'appdirs'],
    tests_require=['pytest'],
    url="https://github.com/KimiNewt/pyshark",
    license="MIT",
    long_description=long_description,
    author="KimiNewt",
    description="Python wrapper for tshark, allowing python packet parsing using wireshark dissectors",
    keywords="wireshark capture packets parsing packet",

    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
)
