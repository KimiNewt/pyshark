import pathlib
import shutil

import platformdirs


def get_cache_dir(tshark_version) -> pathlib.Path:
    cache_dir = pathlib.Path(platformdirs.user_cache_dir(appname="pyshark", version=tshark_version))
    if not cache_dir.exists():
        cache_dir.mkdir(parents=True)
    return cache_dir


def clear_cache(tshark_version=None):
    shutil.rmtree(get_cache_dir(tshark_version))
