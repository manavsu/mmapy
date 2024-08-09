import os
import sys
import logging
import ctypes

log = logging.getLogger("mmapy")

def check_root_access():
    if os.name == 'nt':
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except AttributeError:
            is_admin = False
        if not is_admin:
            log.critical("This process is not running with administrative privileges. Please run as administrator.")
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            log.warn("This process is not running as root. Re-executing with sudo...")
            os.execvp("sudo", ["sudo", "python3"] + sys.argv)