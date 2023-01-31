"""Module used for the actual running of TShark"""
import json

from packaging import version
import os
import subprocess
import sys
import re

from pyshark.config import get_config


class TSharkNotFoundException(Exception):
    pass


class TSharkVersionException(Exception):
    pass


_TSHARK_INTERFACE_ALIAS_PATTERN = re.compile(r"[0-9]*\. ([^\s]*)(?: \((.*)\))?")


def get_process_path(tshark_path=None, process_name="tshark"):
    """Finds the path of the tshark executable.

    If the user has provided a path
    or specified a location in config.ini it will be used. Otherwise default
    locations will be searched.

    :param tshark_path: Path of the tshark binary
    :raises TSharkNotFoundException in case TShark is not found in any location.
    """
    possible_paths = []
    # Check if `config.ini` exists in the current directory or the pyshark directory
    config = get_config()
    if config:
        possible_paths.append(config.get(process_name, f"{process_name}_path"))

    # Add the user provided path to the search list
    if tshark_path is not None:
        user_tshark_path = os.path.join(os.path.dirname(tshark_path),
                                        f"{process_name}.exe" if sys.platform.startswith("win") else process_name)
        possible_paths.insert(0, user_tshark_path)

    # Windows search order: configuration file"s path, common paths.
    if sys.platform.startswith("win"):
        for env in ("ProgramFiles(x86)", "ProgramFiles"):
            program_files = os.getenv(env)
            if program_files is not None:
                possible_paths.append(
                    os.path.join(program_files, "Wireshark", f"{process_name}.exe")
                )
    # Linux, etc. search order: configuration file's path, the system's path
    else:
        os_path = os.getenv(
            "PATH",
            "/usr/bin:/usr/sbin:/usr/lib/tshark:/usr/local/bin"
        )
        for path in os_path.split(":"):
            possible_paths.append(os.path.join(path, process_name))
    if sys.platform.startswith("darwin"):
        possible_paths.append(f"/Applications/Wireshark.app/Contents/MacOS/{process_name}")

    for path in possible_paths:
        if os.path.exists(path):
            if sys.platform.startswith("win"):
                path = path.replace("\\", "/")
            return path
    raise TSharkNotFoundException(
        "TShark not found. Try adding its location to the configuration file. "
        f"Searched these paths: {possible_paths}"
    )


def get_tshark_version(tshark_path=None):
    parameters = [get_process_path(tshark_path), "-v"]
    with open(os.devnull, "w") as null:
        version_output = subprocess.check_output(parameters, stderr=null).decode("ascii")

    version_line = version_output.splitlines()[0]
    pattern = r'.*\s(\d+\.\d+\.\d+).*'  # match " #.#.#" version pattern
    m = re.match(pattern, version_line)
    if not m:
        raise TSharkVersionException("Unable to parse TShark version from: {}".format(version_line))
    version_string = m.groups()[0]  # Use first match found

    return version.parse(version_string)


def tshark_supports_duplicate_keys(tshark_version):
    return tshark_version >= version.parse("2.6.7")


def tshark_supports_json(tshark_version):
    return tshark_version >= version.parse("2.2.0")


def get_tshark_display_filter_flag(tshark_version):
    """Returns '-Y' for tshark versions >= 1.10.0 and '-R' for older versions."""
    if tshark_version >= version.parse("1.10.0"):
        return "-Y"
    else:
        return "-R"


def get_tshark_interfaces(tshark_path=None):
    """Returns a list of interface numbers from the output tshark -D.

    Used internally to capture on multiple interfaces.
    """
    parameters = [get_process_path(tshark_path), "-D"]
    with open(os.devnull, "w") as null:
        tshark_interfaces = subprocess.check_output(parameters, stderr=null).decode("utf-8")

    return [line.split(" ")[1] for line in tshark_interfaces.splitlines() if '\\\\.\\' not in line]


def get_all_tshark_interfaces_names(tshark_path=None):
    """Returns a list of all possible interface names. Some interfaces may have aliases"""
    parameters = [get_process_path(tshark_path), "-D"]
    with open(os.devnull, "w") as null:
        tshark_interfaces = subprocess.check_output(parameters, stderr=null).decode("utf-8")

    all_interface_names = []
    for line in tshark_interfaces.splitlines():
        matches = _TSHARK_INTERFACE_ALIAS_PATTERN.findall(line)
        if matches:
            all_interface_names.extend([name for name in matches[0] if name])
    return all_interface_names


def get_ek_field_mapping(tshark_path=None):
    parameters = [get_process_path(tshark_path), "-G", "elastic-mapping"]
    with open(os.devnull, "w") as null:
        mapping = subprocess.check_output(parameters, stderr=null).decode("ascii")

    mapping = json.loads(
        mapping,
        object_pairs_hook=_duplicate_object_hook)["mappings"]
    # If using wireshark 4, the key "mapping" contains what we want,
    if "dynamic" in mapping and "properties" in mapping:
        pass
    # if using wireshark 3.5 to < 4 the data in "mapping.doc",
    elif "doc" in mapping:
        mapping = mapping["doc"]
    # or "mapping.pcap_file" if using wireshark < 3.5
    elif "pcap_file" in mapping:
        mapping = mapping["pcap_file"]
    else:
        raise TSharkVersionException(f"Your tshark version does not support elastic-mapping. Please upgrade.")

    return mapping["properties"]["layers"]["properties"]


def _duplicate_object_hook(ordered_pairs):
    """Make lists out of duplicate keys."""
    json_dict = {}
    for key, val in ordered_pairs:
        existing_val = json_dict.get(key)
        if not existing_val:
            json_dict[key] = val
        else:
            # There are duplicates without any data for some reason, if it's that - drop it
            # Otherwise, override
            if val.get("properties") != {}:
                json_dict[key] = val

    return json_dict
