#!/bin/bash
"""
    @file    elfpy.py
    @note    process an elf file
"""
import sys
import struct
import argparse
#from builtins import False, True

# 0.0.1    Initial concept + realization
TOOL_VERSION = "0.0.1"

class elf:
    def __init__(self):
        self.fileName = None
        self.versbose_mode = False
        
        self.e_ident = 0
    
    def trace(self,trace_string=None, trace_enable= False):
        if trace_enable is False:
            return

        sys.stdout.write("[INFO] {}\n".format(trace_string))
        
    def set_verbose_mode(self, verbosity=True):
        self.versbose_mode = verbosity

    def process_line(self, elf_file_handle):
        self.trace("process_line", True)

        return 0

    def header_ident_read(self, elf_file_handle):
        """
            read first 16 bytes of header (e_ident)
        """
        self.trace("<process_header> Starts", True)

        self.e_ident = struct.unpack('16B',elf_file_handle.read(16))
        print(self.e_ident)
        self.trace("<process_header> Ends", True)

        return 0

    def header_ident_show(self):
        return 0

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
    except Exception as error:
        sys.stderr.write('[ERROR] {}'.format(error))
        sys.stderr.write(type(error))

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

    elf_file_handle = file_open(args.files)
    elfer = elf()
    elfer.header_ident_read(elf_file_handle)
    
if __name__ == "__main__":
    main()
