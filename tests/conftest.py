import sys
import locale
import platform

import hashsum


def pytest_report_header(config):
    # if config.getoption('verbose') > 0:
    return [
        f'hashsum version:      {hashsum.__version__}',
        f'Platform:             {platform.platform()}',
        f'Byte-ordering:        {sys.byteorder}',
        f'Default encoding:     {sys.getdefaultencoding()}',
        f'Default FS encoding:  {sys.getfilesystemencoding()}',
        f'Default locale:       {locale.getdefaultlocale()}',
    ]
