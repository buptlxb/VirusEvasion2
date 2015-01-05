# -*- coding: utf-8 -*-
import BasicHeader


tableString1 = '''
  0	2	Machine	The number that identifies the type of target machine. For more information, see section 3.3.1, "Machine Types."
  2	2	NumberOfSections	The number of sections. This indicates the size of the section table, which immediately follows the headers.
  
  4	4	TimeDateStamp	The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value), that indicates when the file was created.
  8	4	PointerToSymbolTable	The file offset of the COFF symbol table, or zero if no COFF symbol table is present. This value should be zero for an image because COFF debugging information is deprecated.
12	4	NumberOfSymbols	The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table. This value should be zero for an image because COFF debugging information is deprecated.

16	2	SizeOfOptionalHeader	The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file. For a description of the header format, see section 3.4, "Optional Header (Image Only)."
18	2	Characteristics	The flags that indicate the attributes of the file. For specific flag values, see section 3.3.2, "Characteristics.""
'''
format1 = '2H 3I 2H'


class COFFFileHeader(BasicHeader.HeteHeader):
    """Represent the COFF File Header.

    At the beginning of an object file, or immediately after the signature of an image file, is a standard COFF file header in the following format. Note that the Windows loader limits the number of sections to 96.
    """

    def parse(self, data, file_pointer):
        self.set_attributes_by_table(data, file_pointer, format1, tableString1)

    def get_regions(self):
        r = [(self.fp, self.size, 'COFF File Header')]
        r += [(self.PointerToSymbolTable, self.NumberOfSymbols * 18, 'Symbol Table (by CFH)')]
        r += [(self.fp + self.size, self.SizeOfOptionalHeader, 'Optional Header (by CFH)')]
        return r


if __name__ == '__main__':
    import PE

    pe = PE.PE('helloworld.exe', parse=False)
    header = COFFFileHeader(pe.data, 0xe0 + 4)
    print header
    print header.doc(0)
    
        
    