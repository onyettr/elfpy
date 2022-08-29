#!/bin/bash
"""
    @file    elfpy.py
    @note    process an elf file
"""
import sys
import argparse
import elfparse

#from builtins import False, True

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

def file_open(elf_file_name):
    """
        open elf file
    """
    file_handle = None
    try:
        file_handle = open(elf_file_name,"rb")
    except FileNotFoundError:
        sys.stderr.write('[ERROR] File not found {}'.format(elf_file_name))
        sys.exit(-1)
    except Exception as error:
        sys.stderr.write('[ERROR] {}'.format(error))
        sys.stderr.write(type(error))
        sys.exit(-1)

    return file_handle

def main():
    """
        Process an elf file
    """
    check_environment()

    # Deal with Command Line
    parser = argparse.ArgumentParser(description=
                                     'elf parser')
    parser.add_argument("-f", "--files", type=str,
                        default="elf_filename.elf",
                        help="ELF files")
#    parser.add_argument("elf_filename", type=str,
#                        help="ELF files")
    parser.add_argument("-V" , "--version",
                        help="Display Version Number", action="store_true")
    parser.add_argument("-v" , "--verbose",
                        help="verbosity mode", action="store_true")
    args = parser.parse_args()
    if args.version:
        print(TOOL_VERSION)
        sys.exit(1)

    # Parse the ELF file
    elf_file_handle = file_open(args.files)
    elfer = elfparse.elfParse()
    elfer.set_verbose_mode(args.verbose)
    elfer.set_file_name(args.files)
    elfer.header_ident_parse(elf_file_handle)

    elfer.header_ident_show()

if __name__ == "__main__":
    main()
