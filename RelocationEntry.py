# -*- coding: utf-8 -*-

import BasicHeader

tableString1 = r'''
    0	4	VirtualAddress	The address of the item to which relocation is applied. This is the offset from the beginning of the section, plus the value of the section’s RVA/Offset field. See section 4, “Section Table (Section Headers).” For example, if the first byte of the section has an address of 0x10, the third byte has an address of 0x12.
    4	4	SymbolTableIndex	A zero-based index into the symbol table. This symbol gives the address that is to be used for the relocation. If the specified symbol has section storage class, then the symbol’s address is the address with the first section of the same name.
    8	2	Type	A value that indicates the kind of relocation that should be performed. Valid relocation types depend on machine type. See section 5.2.1, “Type Indicators.”
'''
format1 = '2I H'


class RelocationEntry(BasicHeader.HomoHeader):
    """Represent an Relocation Entry.

    For each section in an object file, an array of fixed-length records holds the section’s COFF relocations. The position and length of the array are specified in the section header.
    """

    def parse(self, data, file_pointer):
        self.set_attributes_by_table(data, file_pointer, format1, tableString1)

    def validate(self):
        return

    def get_regions(self):
        r = []
        return r


if __name__ == '__main__':
    import PE

    pe = PE.PE('helloworld.exe', parse=False)
    print 'no relocation entry in helloworld.exe'