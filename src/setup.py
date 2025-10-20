import os
from setuptools import setup, find_packages

# Read README for long description
try:
    with open(os.path.join(os.path.dirname(__file__), '..', 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "Enhanced Python wrapper for tshark with comprehensive display filters and WPA/WPA2 decryption capabilities."

setup(
    name="pyshark-enhanced",
    version="0.7.0",
    packages=find_packages(),
    package_data={'': ['*.ini', '*.pcapng', '*.yaml', '*.json']},
    install_requires=[
        'lxml>=4.6.0',
        'termcolor>=1.1.0',
        'packaging>=20.0',
        'appdirs>=1.4.0',
        'py>=1.8.0'
    ],
    extras_require={
        'dev': ['pytest>=6.0', 'pytest-cov', 'flake8', 'black'],
        'test': ['pytest>=6.0', 'pytest-cov']
    },
    python_requires='>=3.7',
    url="https://github.com/D14b0l1c/pyshark",
    license="MIT",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="D14b0l1c",
    author_email="",
    description="Enhanced Python wrapper for tshark with display filters and WPA decryption",
    keywords="wireshark tshark capture packets parsing packet analysis network security wpa decryption display filters",
    
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: System :: Networking',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    project_urls={
        'Bug Reports': 'https://github.com/D14b0l1c/pyshark/issues',
        'Source': 'https://github.com/D14b0l1c/pyshark',
        'Documentation': 'https://github.com/D14b0l1c/pyshark/blob/feature/pyshark-enhancements/README.md',
    },
)
