#!/bin/bash
"""
    @file    main.py
    @note    process an elf file
"""
import sys
import argparse
import elfparse

# Tool version
# 0.1.0    Concept + Relization
# 0.1.1    ELF header parsing
# 0.1.2    Program header parse
# 0.1.3    Section header parse
# 0.1.4    Section header (sh_num) decode, flags decoding
VERSION_STRING = "0.1.4"

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
    parser.add_argument("-e" , "--elf",
                        help="Display ELF header", action="store_true")
    parser.add_argument("-s" , "--section",
                        help="Display section header", action="store_true")
    parser.add_argument("-p" , "--program",
                        help="Display program header", action="store_true")

    parser.add_argument("-V" , "--version",
                        help="Display Version Number", action="store_true")
    parser.add_argument("-v" , "--verbose",
                        help="verbosity mode", action="store_true")
    args = parser.parse_args()

    if args.version:
        print(VERSION_STRING)
        sys.exit(1)

    # Parse the ELF file
    elf_file_handle = file_open(args.files) # This should be done in teh class

    elfer = elfparse.elfParse()
    elfer.set_verbose_mode(args.verbose)
    elfer.set_file_name(args.files)
    elfer.elf_header_parse(elf_file_handle)
    elfer.program_header_parse(elf_file_handle)
    elfer.section_header_parse(elf_file_handle)

    if args.section:
        elfer.section_header_show()
    if args.elf:
        elfer.elf_header_show()
    if args.program:
        elfer.program_header_show()

if __name__ == "__main__":
    main()
