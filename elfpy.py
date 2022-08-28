#!/bin/bash
"""
    @file    elfpy.py
    @note    process an elf file
"""
import sys
import argparse


# 0.0.1    Initial concept + realization
TOOL_VERSION = "0.0.1"

def check_environment():
    """
        check_environment
        See if python version is 3 or above
    """
    if sys.version_info.major == 2:
        sys.stderr.write('[ERROR] Must Python 3 for this application')
        sys.exit(-1)

    return 0

def file_open(fs):
    return 0

def main():
    """
        Process an elf file
    """
    check_environment()

    # Deal with Command Line
    parser = argparse.ArgumentParser(description=
                                     'elf parser')
    parser.add_argument("-d" , "--discover", action='store_true', \
                        default=False, help="COM port discovery")
    parser.add_argument("-f", "--files", type=str,
                        default="file.elf",
                        help="ELF files")
    parser.add_argument("-V" , "--version",
                        help="Display Version Number", action="store_true")
    parser.add_argument("-v" , "--verbose",
                        help="verbosity mode", action="store_true")
    args = parser.parse_args()
    if args.version:
        print(TOOL_VERSION)
        sys.exit(1)

if __name__ == "__main__":
    main()
