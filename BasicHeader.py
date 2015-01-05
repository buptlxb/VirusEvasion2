# -*- coding: utf-8 -*-

import struct
import re


class HeteHeader:
    """Represent a header

    """

    def __init__(self, data, file_pointer):
        self.format = ''
        self.size = 0
        self.fieldNames = []
        self.__evdoc__ = {}
        self.fp = file_pointer
        self.parse(data, file_pointer)
        self.validate()
        return

    def parse(self, data, file_pointer):
        assert False, self.__class__.__name__ + '.parse() must be overridden!.'

    def __str__(self):
        s = '%s, %d bytes from 0x%x.\n' % (self.__class__.__name__, self.size, self.fp)

        maxlen = max([len(x) for x in self.fieldNames])
        s += '%-*s | %16s | %s\n%s\n' % (maxlen, 'Field Name', 'high <- low  ', 'Value', '-' * 56)
        for f in self.fieldNames:
            s += '%-*s | %16s | %s\n' % (maxlen, f, getattr(self, f + 'Raw')[::-1].encode('hex')[:16], getattr(self, f))
        s += '%s\n%-*s | %16s | %s\n' % ('-' * 56, maxlen, 'Field Name', 'high <- low  ', 'Value')
        return s

    def doc(self, what=''):
        """Return the description of a field"""
        return self.__evdoc__[str(what).lower()]

    def validate(self):
        """Validation check"""
        return

    def process_table(self, table_string, left=True):
        offsets, sizes, names, descriptions = [], [], [], []
        index_by_slash = 0 if left else -1
        regex = re.compile('^[a-zA-Z ]+')

        lines = table_string.strip().split('\n')
        for line in lines:
            if not line.strip():
                continue
            offset, size, name, description = line.strip().split('\t')
            offsets.append(int(offset.split('/')[index_by_slash]))
            sizes.append(int(size.split('/')[index_by_slash]))
            names.append(regex.match(name).group(0).replace(' ', ''))
            descriptions.append('%s\n%s bytes from %s\n' % (name, size, offset) + description.replace('. ', '.\n'))

        return offsets, sizes, names, descriptions

    def set_attributes(self, data, file_pointer, format_string, offsets, sizes, names, descriptions):
        values = struct.unpack_from('<' + format_string, data, file_pointer + offsets[0])
        assert len(values) == len(offsets) == len(sizes) == len(names) == len(descriptions)
        for i in range(len(values)):
            setattr(self, names[i], values[i])
            setattr(self, names[i] + 'Raw', data[file_pointer + offsets[i]:file_pointer + offsets[i] + sizes[i]])

        self.format += format_string
        self.size += struct.calcsize(format_string)
        self.fieldNames += names
        newdoc1 = [(str(offsets[i]), descriptions[i]) for i in range(len(offsets))]
        newdoc2 = [(names[i], descriptions[i]) for i in range(len(offsets))]
        self.__evdoc__ = dict(self.__evdoc__.items() + newdoc1 + newdoc2)

    def set_attributes_by_table(self, data, file_pointer, format_string, table_string):
        info = self.process_table(table_string)
        self.set_attributes(data, file_pointer, format_string, *info)

    def write(self):
        return struct.pack(self.format, *[getattr(self, x) for x in self.fieldNames])


class HomoHeader(HeteHeader):
    def process_table(self, table_string, left=True):

        if not hasattr(self.__class__, 'info'):
            offsets, sizes, names, descriptions = [], [], [], []
            index_by_slash = 0 if left else -1
            regex = re.compile('^[a-zA-Z ]+')

            lines = table_string.strip().split('\n')
            for line in lines:
                if not line.strip():
                    continue
                offset, size, name, description = line.strip().split('\t')
                offsets.append(int(offset.split('/')[index_by_slash]))
                sizes.append(int(size.split('/')[index_by_slash]))
                names.append(regex.match(name).group(0).replace(' ', ''))
                descriptions.append('%s\n%s bytes from %s\n' % (name, size, offset) + description.replace('. ', '.\n'))

            self.__class__.info = offsets, sizes, names, descriptions
        return self.__class__.info

    def set_attributes(self, data, file_pointer, format_string, offsets, sizes, names, descriptions):
        values = struct.unpack_from('<' + format_string, data, file_pointer + offsets[0])
        assert len(values) == len(offsets) == len(sizes) == len(names) == len(descriptions)
        for i in range(len(values)):
            setattr(self, names[i], values[i])
            setattr(self, names[i] + 'Raw', data[file_pointer + offsets[i]:file_pointer + offsets[i] + sizes[i]])
        self.size = struct.calcsize(format_string)

        if not hasattr(self.__class__, 'format'):
            self.__class__.format = format_string
            self.__class__.fieldNames = names
            newdoc1 = [(str(offsets[i]), descriptions[i]) for i in range(len(offsets))]
            newdoc2 = [(names[i], descriptions[i]) for i in range(len(offsets))]
            self.__class__.__evdoc__ = dict(self.__evdoc__.items() + newdoc1 + newdoc2)

        self.format = self.__class__.format
        self.fieldNames = self.__class__.fieldNames
        self.__evdoc__ = self.__class__.__evdoc__


class BasicHeader:
    """Represent the basic header."""

    tableString = None

    def __init__(self, data, file_pointer):
        self.filePointer = file_pointer
        self.size = 9
        self.rawData = []
        self.fields = []
        self.__evdoc__ = ''
        self.set_attributes_from_split_table_string(data[file_pointer:])
        self.validate()

    def __str__(self):
        s = '%s, %d bytes from 0x%x.\n' % (self.__class__.__name__, self.size, self.filePointer)

        maxlen = max([len(x) for x in self.fields])
        s += '%-*s | %16s | %4s | %s\n%s\n' % (maxlen, 'Field Name', 'high <- low  ', 'Type', 'Value', '-' * 56)
        for f in self.fields:
            s += '%-*s | %16s | %4s | %s\n' % (
                maxlen, f, getattr(self, f + 'Raw')[::-1].encode('hex')[:16], getattr(self, f + 'Type'),
                getattr(self, f))
        s += '%s\n%-*s | %16s | %4s | %s\n' % ('-' * 56, maxlen, 'Field Name', 'high <- low  ', 'Type', 'Value')
        return s

    def doc(self, what=''):
        """Return the description of a field"""
        return self.__evdoc__[str(what).lower()]

    def validate(self):
        """Validation check"""
        return

    def split_table_string(self, data):
        """Extract an array from table content string.

        The string uses '\\n' and '\\t' to separate rows and columns."""

        lines = self.tableString.strip().split('\n')
        d = []
        for line in lines:
            cells = line.strip().split('\t')
            d.append([cell.strip() for cell in cells])
        self.tableString = d

    def set_attributes_from_split_table_string(self, data):
        """Set attributes according to the split table string"""

        def recognize_type(size_by_bytes, description):
            words = description.split('.')[0].split()
            for word in words:
                # if word in ['number', 'index', 'offset', 'size', 'flags', 'integer', 'address', 'alignment', 'Reserved,', 'checksum']:
                # return {1:'B', 2:'H', 4:'I', 8:'Q'}[size]
                if word in ['name', 'string']:
                    return '%ds' % size_by_bytes
                if word in ['any']:
                    return '%dc' % size_by_bytes
            return {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}[size_by_bytes]

        self.split_table_string(data)

        ending = 0
        fields = []
        doc = {}
        for line in self.tableString:
            offset, size, name, desc = line
            offset = int(offset)
            size = int(size)
            ending = offset + size if offset + size > ending else ending

            fields.append((offset, name))
            doc[str(offset)] = name + '(%d bytes from %d). ' % (size, offset) + desc
            doc[name.lower()] = doc[str(offset)]
            setattr(self, name + 'Raw', data[offset:offset + size])
            attr_type = recognize_type(size, desc)
            setattr(self, name + 'Type', attr_type)
            setattr(self, name, struct.unpack(attr_type, data[offset:offset + size])[0])

        fields = [x[1] for x in sorted(fields)]
        doc[''] = [doc[x.lower()] for x in fields]

        self.size = ending
        self.rawData = data[:ending]
        self.fields = fields
        self.__evdoc__ = doc

    def get_regions(self):
        assert 'this function must be overridden!'
        return []


if __name__ == '__main__':
    import doctest

    doctest.testmod()