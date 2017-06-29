"""
Module used for the actual running of TShark
"""
from distutils.version import LooseVersion
import os
import subprocess
import sys
import re

from pyshark.config import get_config


class TSharkNotFoundException(Exception):
    pass


class TSharkVersionException(Exception):
    pass


def check_output(*popenargs, **kwargs):
    """
    For Python 2.6 compatibility. Taken from https://hg.python.org/cpython/file/d37f963394aa/Lib/subprocess.py#l544

    Run command with arguments and return its output as a byte string.

    If the exit code was non-zero it raises a CalledProcessError.  The
    CalledProcessError object will have the return code in the returncode
    attribute and output in the output attribute.

    The arguments are the same as for the Popen constructor.  Example:

    >>> check_output(["ls", "-l", "/dev/null"])
    'crw-rw-rw- 1 root root 1, 3 Oct 18  2007 /dev/null\n'

    The stdout argument is not allowed as it is used internally.
    To capture standard error in the result, use stderr=STDOUT.

    >>> check_output(["/bin/sh", "-c",
    ...               "ls -l non_existent_file ; exit 0"],
    ...              stderr=STDOUT)
    'ls: non_existent_file: No such file or directory\n'
    """
    #if sys.version_info.major > 2 or sys.version_info.minor >= 7:
    #    return subprocess.check_output(*popenargs, **kwargs)

    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden.')
    process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        cmd = kwargs.get("args")
        if cmd is None:
            cmd = popenargs[0]
        raise RuntimeError("Program failed to run. Retcode: %d. Cmd: %s" % (retcode, cmd))
    return output


def get_process_path(tshark_path=None, process_name='tshark'):
    """
    Finds the path of the tshark executable. If the user has provided a path
    or specified a location in config.ini it will be used. Otherwise default
    locations will be searched.

    :param tshark_path: Path of the tshark binary
    :raises TSharkNotFoundException in case TShark is not found in any location.
    """
    config = get_config()
    possible_paths = [config.get('tshark', 'tshark_path')]

    # Add the user provided path to the search list
    if tshark_path is not None:
        possible_paths.insert(0, tshark_path)

    # Windows search order: configuration file's path, common paths.
    if sys.platform.startswith('win'):
        for env in ('ProgramFiles(x86)', 'ProgramFiles'):
            program_files = os.getenv(env)
            if program_files is not None:
                possible_paths.append(
                    os.path.join(program_files, 'Wireshark', '%s.exe' % process_name)
                )
    # Linux, etc. search order: configuration file's path, the system's path
    else:
        os_path = os.getenv(
            'PATH',
            '/usr/bin:/usr/sbin:/usr/lib/tshark:/usr/local/bin'
        )
        for path in os_path.split(':'):
            possible_paths.append(os.path.join(path, process_name))

    for path in possible_paths:
        if os.path.exists(path):
            return path
    raise TSharkNotFoundException(
        'TShark not found. Try adding its location to the configuration file. '
        'Search these paths: {}'.format(possible_paths)
    )


def get_tshark_version(tshark_path=None):
    parameters = [get_process_path(tshark_path), '-v']
    with open(os.devnull, 'w') as null:
        version_output = check_output(parameters, stderr=null).decode("ascii")

    version_line = version_output.splitlines()[0]
    pattern = '.*\s(\d+\.\d+\.\d+).*'  # match " #.#.#" version pattern
    m = re.match(pattern, version_line)
    if not m:
        raise TSharkVersionException('Unable to parse TShark version from: {}'.format(version_line))
    version_string = m.groups()[0]  # Use first match found

    return version_string


def tshark_supports_json(tshark_path=None):
    tshark_version = get_tshark_version(tshark_path)
    return LooseVersion(tshark_version) >= LooseVersion("2.2.0")


def get_tshark_display_filter_flag(tshark_path=None):
    """
    Returns '-Y' for tshark versions >= 1.10.0 and '-R' for older versions.
    """
    tshark_version = get_tshark_version(tshark_path)
    if LooseVersion(tshark_version) >= LooseVersion("1.10.0"):
        return '-Y'
    else:
        return '-R'


def get_tshark_interfaces(tshark_path=None):
    """
    Returns a list of interface numbers from the output tshark -D. Used
    internally to capture on multiple interfaces.
    """
    parameters = [get_process_path(tshark_path), '-D']
    with open(os.devnull, 'w') as null:
        tshark_interfaces = check_output(parameters, stderr=null).decode("ascii")

    return [line.split('.')[0] for line in tshark_interfaces.splitlines()]
