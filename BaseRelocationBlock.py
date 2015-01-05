# -*- coding: utf-8 -*-
import struct

import BasicHeader


class BaseRelocationBlock(BasicHeader.BasicHeader):
    """Represent a Base Relocation Block.

    The base relocation table contains entries for all base relocations in the image. The Base Relocation Table field in the optional header data directories gives the number of bytes in the base relocation table. For more information, see section 3.4.3, “Optional Header Data Directories (Image Only).” The base relocation table is divided into blocks. Each block represents the base relocations for a 4K page. Each block must start on a 32-bit boundary.
    The loader is not required to process base relocations that are resolved by the linker, unless the load image cannot be loaded at the image base that is specified in the PE header.
    """

    tableString = r'''
    0	4	Page RVA	The image base plus the page RVA is added to each offset to create the VA where the base relocation must be applied.
4	4	Block Size	The total number of bytes in the base relocation block, including the Page RVA and Block Size fields and the Type/Offset fields that follow.
'''

    def split_table_string(self, data):
        """Extract an array from table content string.

        The string uses '\\n' and '\\t' to separate rows and columns."""

        self.size = struct.unpack('I', data[4:8])[0]
        self.tableString += '8\t%d\tTypeAndOffset\tThe Block Size field is then followed by any number of Type or Offset field entries. Each entry is a WORD (2 bytes).' % (
            self.size - 8)

        super(BaseRelocationBlock, self).split_table_string(data)

    def validate(self):
        return

    def get_regions(self):
        r = [(self.filePointer, self.size, 'Base Relocation Block')]
        return r


if __name__ == '__main__':
    import PE

    pe = PE.PE('helloworld.exe', parse=False)
    fp = 0x7600
    while fp < 0x7954:
        header = BaseRelocationBlock(pe.data, fp)
        fp += header.size
        print header