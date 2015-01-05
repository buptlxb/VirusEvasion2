# -*- coding: utf-8 -*-
import BasicHeader
from Consts import *

tableString1 = '''
  0	2	Magic	The unsigned integer that identifies the state of the image file. The most common number is 0x10B, which identifies it as a normal executable file. 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable.
  2	1	MajorLinkerVersion	The linker major version number.
  3	1	MinorLinkerVersion	The linker minor version number.
  4	4	SizeOfCode	The size of the code (text) section, or the sum of all code sections if there are multiple sections.
  8	4	SizeOfInitializedData	The size of the initialized data section, or the sum of all such sections if there are multiple data sections.
12	4	SizeOfUninitializedData	The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections.
16	4	AddressOfEntryPoint	The address of the entry point relative to the image base when the executable file is loaded into memory. For program images, this is the starting address. For device drivers, this is the address of the initialization function. An entry point is optional for DLLs. When no entry point is present, this field must be zero.
20	4	BaseOfCode	The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
'''
format1 = 'H 2B 5I'

tableString2 = '''
24	4	BaseOfData	The address that is relative to the image base of the beginning-of-data section when it is loaded into memory.
'''
format2 = 'I'

tableString3 = '''
28/24	4/8	ImageBase	The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
32/32	4	SectionAlignment	The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
36/36	4	FileAlignment	The alignment factor (in bytes) that is used to align the raw data of sections in the image file. The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512. If the SectionAlignment is less than the architecture’s page size, then FileAlignment must match SectionAlignment.
40/40	2	MajorOperatingSystemVersion	The major version number of the required operating system.
42/42	2	MinorOperatingSystemVersion	The minor version number of the required operating system.
44/44	2	MajorImageVersion	The major version number of the image.
46/46	2	MinorImageVersion	The minor version number of the image.
48/48	2	MajorSubsystemVersion	The major version number of the subsystem.
50/50	2	MinorSubsystemVersion	The minor version number of the subsystem.
52/52	4	Win32VersionValue	Reserved, must be zero.
56/56	4	SizeOfImage	The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment.
60/60	4	SizeOfHeaders	The combined size of an MS DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment.
64/64	4	CheckSum	The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process.
68/68	2	Subsystem	The subsystem that is required to run this image. For more information, see “Windows Subsystem” later in this specification.
70/70	2	DllCharacteristics	For more information, see “DLL Characteristics” later in this specification.
72/72	4/8	SizeOfStackReserve	The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached.
76/80	4/8	SizeOfStackCommit	The size of the stack to commit.
80/88	4/8	SizeOfHeapReserve	The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached.
84/96	4/8	SizeOfHeapCommit	The size of the local heap space to commit.
88/104	4	LoaderFlags	Reserved, must be zero.
92/108	4	NumberOfRvaAndSizes	The number of data-directory entries in the remainder of the optional header. Each describes a location and size.
'''
format3 = '3I 6H 4I 2H 6I'  # , '< Q 2I 6H 4I 2H 4Q 2I'

tableString4 = '''
96/112	8	Export Table	The export table address and size. For more information see section 6.3, “The .edata Section (Image Only).”
104/120	8	Import Table	The import table address and size. For more information, see section 6.4, “The .idata Section.”
112/128	8	Resource Table	The resource table address and size. For more information, see section 6.9, “The .rsrc Section.”
120/136	8	Exception Table	The exception table address and size. For more information, see section 6.5, “The .pdata Section.”
128/144	8	Certificate Table	The attribute certificate table address and size. For more information, see section 5.7, “The attribute certificate table (Image Only).”
136/152	8	Base Relocation Table	The base relocation table address and size. For more information, see section 6.6, “The .reloc Section (Image Only).”
144/160	8	Debug	The debug data starting address and size. For more information, see section 6.1, “The .debug Section.”
152/168	8	Architecture	Reserved, must be 0
160/176	8	Global Ptr	The RVA of the value to be stored in the global pointer register. The size member of this structure must be set to zero. 
168/184	8	TLS Table	The thread local storage (TLS) table address and size. For more information, see section 6.7, “The .tls Section.”
176/192	8	Load Config Table	The load configuration table address and size. For more information, see section 6.8, “The Load Configuration Structure (Image Only).”
184/200	8	Bound Import	The bound import table address and size. 
192/208	8	IAT	The import address table address and size. For more information, see section 6.4.4, “Import Address Table.”
200/216	8	Delay Import Descriptor	The delay import descriptor address and size. For more information, see section 5.8, “Delay-Load Import Tables (Image Only).”
208/224	8	CLR Runtime Header	The CLR runtime header address and size. For more information, see section 6.10, “The .cormeta Section (Object Only).”
216/232	8	Reserved	Reserved, must be zero
'''
# format4 = '16Q'  # should be generated according to NumberOfRvaAndSizes


class OptionalHeader(BasicHeader.HeteHeader):
    """Represent the Optional Header.

    The first eight fields of the optional header are standard fields that are defined for every implementation of COFF.
    These fields contain general information that is useful for loading and running an executable file.
    They are unchanged for the PE32+ format.
    """

    def parse(self, data, file_pointer):
        self.set_attributes_by_table(data, file_pointer, format1, tableString1)

        assert self.Magic == PE32_MAGIC_NUMBER, 'not PE'

        self.set_attributes_by_table(data, file_pointer, format2, tableString2)
        self.set_attributes_by_table(data, file_pointer, format3, tableString3)

        n = self.NumberOfRvaAndSizes
        info = self.process_table(tableString4, True)
        format4, offsets, sizes, names, descriptions = '%dI' % (n * 2), xrange(self.size, self.size + n * 8, 4), [
            4] * 2 * n, [], []
        for i in xrange(n):
            names += [info[2][i] + 'RVA', info[2][i] + 'Size']
            descriptions += [info[3][i].replace('address and size.', 'RVA.'),
                             info[3][i].replace('address and size.', 'size.')]
        self.set_attributes(data, file_pointer, format4, offsets, sizes, names, descriptions)

    def get_regions(self):
        r = [(self.fp, self.size, 'Optional Header')]
        r += [(self.ExportTableRVA, self.ExportTableSize, 'Export Table (by DD)', 'RVA')]
        r += [(self.ImportTableRVA, self.ImportTableSize, 'Import Table (by DD)', 'RVA')]
        r += [(self.ResourceTableRVA, self.ResourceTableSize, 'Resource Table (by DD)', 'RVA')]
        r += [(self.ExceptionTableRVA, self.ExceptionTableSize, 'Exception Table (by DD)', 'RVA')]
        r += [(self.CertificateTableRVA, self.CertificateTableSize, 'Certificate Table (by DD)', 'RVA')]
        r += [(self.BaseRelocationTableRVA, self.BaseRelocationTableSize, 'Base Relocation Table (by DD)', 'RVA')]
        r += [(self.DebugRVA, self.DebugSize, 'Debug (by DD)', 'RVA')]
        r += [(self.GlobalPtrRVA, self.GlobalPtrSize, 'Global Ptr (by DD)', 'RVA')]
        r += [(self.TLSTableRVA, self.TLSTableSize, 'TLS Table (by DD)', 'RVA')]
        r += [(self.LoadConfigTableRVA, self.LoadConfigTableSize, 'Load Config Table (by DD)', 'RVA')]
        r += [(self.BoundImportRVA, self.BoundImportSize, 'Bound Import (by DD)', 'RVA')]
        r += [(self.IATRVA, self.IATSize, 'IAT (by DD)', 'RVA')]
        r += [(self.DelayImportDescriptorRVA, self.DelayImportDescriptorSize, 'Delay Import Descriptor (by DD)', 'RVA')]
        r += [(self.CLRRuntimeHeaderRVA, self.CLRRuntimeHeaderSize, 'CLR Runtime Header (by DD)', 'RVA')]

        return r


if __name__ == '__main__':
    import PE

    pe = PE.PE('helloworld.exe', parse=False)
    header = OptionalHeader(pe.data, 0xe4 + 20)
    print header
    print header.doc(0)