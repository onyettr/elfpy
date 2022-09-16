#!/bin/bash
"""
    @file    elfparse.py
    @note    Parse and decode an elf file
"""
# pylint: disable=unused-argument, invalid-name, trailing-whitespace,too-many-instance-attributes
import sys
import struct

# Map e_ident for OS ABI
target_os_lookup = {
        0x00 : "UNIX - System V",
        0x01 : "HP-UX   ",
        0x02 : "NetBSD  ",
        0x03 : "Linux   ",
        0x04 : "GNU Hurd",
        0x05 : "Solaris ",
        0x07 : "AIX     ",
        0x08 : "IRIX    ",
        0x09 : "FreeBSD ",
        0x0A : "Tru64   ",
        0x0B : "Novell Modesto",
        0x0C : "OpenBSD  ",
        0x0D : "OpenVMS  ",
        0x0E : "Nonstop Kernel",
        0x0F : "AROS     ",
        0x10 : "FenixOS  ",
        0x11 : "Nuxi CloudABI",
        0x12 : "Stratus Technologies OpenVOS"
}

e_type_lookup = {
        0x00    : "ET_NONE Unknown",
        0x01    : "ET_REL  Relocatable file",
        0x02    : "ET_EXEC Executable file",
        0x03    : "ET_DYB  Shared object",
        0x04    : "ET_CORE Core file",
        0xFE00  : "ET_LOOS",
        0xFEFF  : "ET_HIOS",
        0xFF00  : "ET_LOPROC",
        0xFFFF  : "ET_HIPROC" 
}

e_version_lookup = {
        0   : "EV_NONE",
        1   : "EV_CURRENT"
}

e_machine_lookup = {
        0x00 : "No specfic instr set",
        0x01 : "AT&T WE 321000",
        0x02 : "SPARC",
        0x03 : "x86",
        0x04 : "M68K",
        0x05 : "M88K",
        0x06 : "Intel MCU",
        0x07 : "Intel 80860",
        0x08 : "MIPS",
        0x09 : "IBM System/370",
        0x0A : "MIPS RS3000 LE",
        0x0B : "<Reserved>",
        0x0C : "<Reserved>",
        0x0D : "<Reserved?",
        0x0E : "HP PA-RISC",
        0X0F : "<Reserved>",
        0x13 : "INTEL 80960",
        0x28 : "ARM", 
        0x29 : "Digital ALPHA",
        0x2A : "SuperH",
        0x2B : "SPARC Version 9",
        0x2C : "Siemens TriCore embedded processor",
        0x2D : "Argonaut RISC Core"
        # Still more to put into here
}

p_type_lookup = {
        0x00000000 : "Unused",
        0x00000001 : "LOAD",
        0x00000002 : "DYNAMIC",
        0x00000003 : "INTERP",
        0x00000004 : "AUX",
        0x00000005 : "RESERVED",
        0x00000006 : "SGM HDR",
        0x00000007 : "RESERVED",
        0x6FFFFFFF : "RESERVED",
        0x70000000 : "RESERVED",
        0x7FFFFFFF : "RESERVED"
}

p_flags_lookup = {
        0 : "None",
        1 : "E",
        2 : "W",
        3 : "WE",
        4 : "R",
        5 : "RE",
        6 : "RW",
        7 : "RWE"
}

s_type_lookup = {
    0x0    :   "NULL",
    0x1    :   "PROGBITS",
    0x2    :   "SYMTAB",
    0x3    :   "STRTAB",
    0x4    :   "RELA",   
    0x5    :   "HADH",
    0x6    :   "DYNAMIC",
    0x7    :   "NOTE",
    0x8    :   "NOBITS",
    0x9    :   "REL",
    0x0A   :   "SHLIB",
    0x0B   :   "DYNSYM",
    0x0E   :   "INIT_ARRAY",
    0x0F   :   "FINI_ARRAY",
    0x10   :   "PREINIT_ARRAY",
    0x11   :   "GROUP",
    0x12   :   "SYMTAB_SHNDX",
    0x13   :   "NUM"
#    0x00000000 :   "LOOS"
}

s_flags_lookup = {
    0x1         :   "SHF_WRITE",
    0x2         :   "SHF_ALLOC",
    0x4         :   "SHF_EXECINSTR",
    0x10        :   "SHF_MERGE",
    0x20        :   "SHF_STRINGS",
    0x40        :   "SHF_INFO_LINK",
    0x80        :   "SHF_LINK_ORDER",
    0x100       :   "SHF_OS_NONCONFORMING",
    0x200       :   "SHF_GRPUP",
    0x400       :   "SHF_TLS",
    0x0FF00000  :   "SHF_MASKOS",
    0xF0000000  :   "SHF_MASKPROC",
    0x4000000   :    "SHF_ORDERED",
    0x8000000   :   "SHF_EXCLUDE"
}

class elfParse(object):
    """
        encapsulate the parser and decoding methods
        store the data from headers
    """
    MAGIC_ELF_MARKER = 0x74
    EI_CLASS = 0x4
    EI_DATA = 0x5
    EI_VERSION = 0x6
    EI_OSABI = 0x7
    EI_ABIVERSION = 0x8
    EI_PAD = 0x9
    
    def __init__(self):
        """
            ctor = 
            @todo oprn the file here
        """
        self.fileName = None
        self.elf_file_handle = 0
        self.verbose_mode = False

        # ELF Header contents
        self.e_ident = 0
        self.e_magic_0 = 0
        self.e_magic_1 = 0
        self.e_magic_2 = 0
        self.e_magic_3 = 0
        self.e_class = 0
        self.e_data = 0
        self.e_version = 0
        self.e_osabi = 0
        self.e_abiversion = 0
        self.e_type = 0
        self.e_machine = 0
        self.e_version = 0
        self.e_entry = 0
        self.e_phoff = 0
        self.e_shoff = 0
        self.e_flags = 0
        self.e_hsize = 0
        self.e_phentsize = 0
        self.e_phnum = 0
        self.e_shentsize = 0
        self.e_shnum = 0
        self.e_shstrndx = 0

        # Program Header contents
        self.ph_entry = []
        self.p_pgm_header = 0
        self.p_type = 0
        self.p_flags = 0
        self.p_offset = 0
        self.p_vaddr = 0
        self.p_paddr = 0
        self.p_filesz = 0
        self.p_memsz = 0
        self.p_align = 0

        # Section Header contents
        self.sh_entry = []
        self.string_table = {}
        self.sh_type = 0
        self.sh_name = 0

    def trace(self,trace_string=None, trace_enable=False):
        """
            trace - internal trace mechanism 
        """
        if trace_enable is False or self.verbose_mode is False:
            return

        sys.stdout.write("[INFO] {}\n".format(trace_string))

    def print_string(self,fmt,*args):
        """
            like a python printf()
        """
        a = fmt % args
        sys.stdout.write(a)

    def set_file_name(self, fileName=None):
        """
           set the filename 
        """
        self.fileName = fileName

    def get_file_name(self):
        """
            get the filaname we are rpocessing
        """
        return self.fileName

    def set_verbose_mode(self, verbosity=True):
        """
            enable verbose mode
        """
        self.verbose_mode = verbosity

    def get_verbose_mode(self):
        """
            return verbose status
        """
        return self.verbose_mode

    def is_elf(self):
        """
            check header to see if this really an ELF file
        """
        if (self.e_magic_1 == ord('E') and
            self.e_magic_2 == ord('L') and
            self.e_magic_3 == ord('F')):
            return True

        return False 

    def flags_to_string(self, flags):
        """
            section header flags - convert to string

            Bit#  1234567890123
            Field WAX MSILOGTCx
        """
        W_MASK  = 0x1       # Write Mask
        A_MASK  = 0x2       # Alloc mask
        X_MASK  = 0x4       # Executable mask
        M_MASK  = 0x10      # M?
        S_MASK  = 0x20
#        I_MASK  = 0x40
#        L_MASK  = 0x80
#        O_MASK  = 0x100
#        G_MASK  = 0x200
#        T_MASK  = 0x400
#        C_MASK  = 0x800

        flag_string = ' '

        if flags & W_MASK:
            flag_string += 'W'

        if flags & A_MASK:
            flag_string += 'A'

        if flags & X_MASK:
            flag_string += 'X'

        if flags & M_MASK:
            flag_string += 'M'

        if flags & S_MASK:
            flag_string += 'S'

        return flag_string

    def elf_header_parse(self,elf_file_handle):
        """
            read first 9 bytes of header (e_ident)
            @todo replace with one read and decode
        """
        self.trace("<process_header> Starts", True)

        self.e_ident = struct.unpack('16B',elf_file_handle.read(16))
        self.trace(self.e_ident,True)

        self.e_magic_0,self.e_magic_1,self.e_magic_2, self.e_magic_3 = self.e_ident[:4]
        self.e_class,self.e_data,self.e_version,self.e_osabi = self.e_ident[4:8]

        if not self.is_elf():
            print("[ERROR] Header is not ELF file")
            sys.exit(-1)

        self.e_type = struct.unpack('H', elf_file_handle.read(2))[0]
        self.e_machine = struct.unpack('H',elf_file_handle.read(2))[0]
        self.e_version = struct.unpack('I',elf_file_handle.read(4))[0]

        # @todo if 64-bit need to read more anotehr 4 bytes
        self.e_entry = struct.unpack('I',elf_file_handle.read(4))[0]
        self.e_phoff = struct.unpack('I',elf_file_handle.read(4))[0]

        self.e_shoff = struct.unpack('I',elf_file_handle.read(4))[0]
        self.e_flags = struct.unpack('I',elf_file_handle.read(4))[0]
        self.e_hsize= struct.unpack('H',elf_file_handle.read(2))[0]
        self.e_phentsize = struct.unpack('H',elf_file_handle.read(2))[0]
        self.e_phnum = struct.unpack('H',elf_file_handle.read(2))[0]
        self.e_shentsize = struct.unpack('H',elf_file_handle.read(2))[0]
        self.e_shnum = struct.unpack('H',elf_file_handle.read(2))[0]
        self.e_shstrndx = struct.unpack('H',elf_file_handle.read(2))[0]

        return 0

    def section_header_parse(self,elf_file_handle):
        """
            parse the Secction Header
        """
        self.trace("<program_header> Starts", True)
        self.elf_file_handle = elf_file_handle

        elf_file_handle.seek(self.e_shoff + self.e_shentsize * self.e_shstrndx)
        section = elf_file_handle.read(48)
        (sh_name,   sh_type, sh_flags, sh_addr, 
         sh_offset, sh_size, sh_link, sh_info, sh_align,sh_entsize) = \
            struct.unpack_from('IIIIIIIIII', bytes(section))

        # Obtain the section names and stroe them in an array at theor 'sh_name' index
        elf_file_handle.seek(sh_offset)
        string_table = elf_file_handle.read(sh_size)

        entry = 0
        count = 0
        for c in string_table:
            if c == 0:
                self.string_table[entry] = string_table[entry:count]
                entry = count + 1
            count = count + 1

        # process each section and concatenate for later processing
        for i in range(0,self.e_shnum):
            section_header_offset = self.e_shoff + (i * self.e_shentsize)
            elf_file_handle.seek(section_header_offset)
            self.sh_entry += elf_file_handle.read(48)

        self.trace("<program_header> Ends", True)

    def program_header_parse(self,elf_file_handle):
        """
            parse the progran header
        """
        self.trace("<program_header> Starts", True)
# DEBUG 
#        elf_file_handle.seek(self.e_phoff+self.e_phentsize * 0)
#        line = elf_file_handle.read(32)
#        self.print_string("".join('%02x ' % i for i in line))
        for each_program_header in range(0,self.e_phnum):
            program_header_offset= elf_file_handle.seek(self.e_phoff
                                 + (self.e_phentsize * each_program_header))
            elf_file_handle.seek(program_header_offset)
            self.ph_entry += elf_file_handle.read(32)

        self.trace("<program_header> Ends", True)

    def program_header_show(self):
        """
            program_header_show - display the program header info
        """
        self.print_string("PROGRAM Header: %s\n", self.get_file_name())
        self.print_string("Type Offset   Vaddr      PAddr      FileSize MemSize  Flag Align\n")

        for i in range(0, self.e_phnum):
            section = self.return_slice (self.ph_entry, i*32, 32)
#            print(''.join('{:02X} '.format(n) for n in section))
            (p_type,p_offset,p_vaddr,p_paddr,p_filesz,p_memsz,p_flags,p_align) = \
                struct.unpack_from('IIIIIIII', bytes(section))
            self.print_string("%s 0x%06x 0x%08x 0x%08x 0x%06x 0x%06x %4s 0x%x\n",
                              p_type_lookup.get(p_type),
                              p_offset,
                              p_vaddr,
                              p_paddr,
                              p_filesz,
                              p_memsz,
                              p_flags_lookup.get(p_flags & 0xF),
                              p_align
                              )

    def elf_header_show(self):
        """
            print out the ELF 'ident' header details
        """
        self.print_string("ELF File Header: %s\n", self.get_file_name())
        self.print_string("EI_MAGIC      ")
        self.print_string("".join('%02x ' % i for i in self.e_ident))
        self.print_string("\t '%c' '%c' '%c'\n",
                          chr(self.e_magic_1),
                          chr(self.e_magic_2),
                          chr(self.e_magic_3))
        if self.e_class == 1:
            class_string = "32-bit"
        elif self.e_class == 2:
            class_string = "64-bit"
        else:
            class_string = ">> UNKNOWN <<"
        self.print_string("EI_CLASS      %02x\tFormat %s\n", 
                          self.e_class, class_string)
        if self.e_class == 1:
            endianess_string = "Little"
        elif self.e_class == 2:
            endianess_string = "Big   "
        else:
            endianess_string = ">> UNKNOWN <<"
        self.print_string("EI_DATA       %02x\tEndianess %s\n", 
                          self.e_data, endianess_string)
        self.print_string("EI_VERSION    %02x\t%s\n", 
                          self.e_version, e_version_lookup.get(self.e_version))
        osabi_string = target_os_lookup.get(self.e_osabi)
        if not osabi_string:
            osabi_string = ">> UNKNOWN OS ABI <<"
        self.print_string("EI_OSABI      %02x\t%s\n", 
                          self.e_osabi, osabi_string)
        self.print_string("EI_ABIVERSION %02x\n", self.e_abiversion)
        self.print_string("E_TYPE        %02x\t%s\n",
                          self.e_type, e_type_lookup.get(self.e_type))
        self.print_string("E_MACHINE     %02x\t%s\n", 
                          self.e_machine, e_machine_lookup.get(self.e_machine))
        self.print_string("E_VERSION     0x%02x\n", 
                          self.e_version)
        self.print_string("E_ENTRY       0x%0x\n", 
                          self.e_entry)
        self.print_string("E_PHOFF       %d bytes\n", 
                          self.e_phoff)
        self.print_string("E_SHOFF       %d bytes\n", 
                          self.e_shoff)
        self.print_string("E_FLAGS       0x%0x\n", 
                          self.e_flags)
        self.print_string("E_EHSIZE      %d bytes\n", 
                          self.e_hsize)
        self.print_string("E_PHENTSIZE   %d bytes\n", 
                          self.e_phentsize)
        self.print_string("E_PHNUM       %d\n", 
                          self.e_phnum)
        self.print_string("E_SHENTSIZE   %d bytes\n", 
                          self.e_shentsize)
        self.print_string("E_SHNUM       %d\n", 
                          self.e_shnum)
        self.print_string("E_SHSTRNDX    %d\n", 
                          self.e_shstrndx)

        return 0

    def return_slice(self,slice_list, start, size):
        return slice_list[start: start+size]

    def section_header_show(self):
        """
            display the section header information
        """
        self.print_string("SECTION Header: %s\n", self.fileName)
        self.print_string("\n Sec#\t\tName\t\tType\t\tAddress\t\tOffset\tSize\tES\tFlag\tLK\tInf\tAL\n")

        for i in range(0, self.e_shnum):
            section = self.return_slice (self.sh_entry, i*48, 48)
#            print(''.join('{:02X} '.format(n) for n in section))
            (sh_name,sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_align,sh_entsize) = \
                struct.unpack_from('IIIIIIIIII', bytes(section))

            self.print_string("%4d\t%-16s\t%-12s\t%08x\t%06x\t%06x\t%02X\t%4s\t%x\t%d\t%d\n",
                              i,
                              self.string_table[sh_name].decode('utf-8'),
                              s_type_lookup.get(sh_type),
                              sh_addr,
                              sh_offset,
                              sh_size,
                              sh_entsize,
                              self.flags_to_string(sh_flags),
                              sh_link,
                              sh_info,
                              sh_align)
