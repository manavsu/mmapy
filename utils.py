import os
import sys
import logging

log = logging.getLogger("mmapy")
def check_root_access():    
    if os.geteuid() != 0:
        log.warn("This process is not running as root. Re-executing with sudo...")
        os.execvp("sudo", ["sudo", "python"] + sys.argv)
        