#!/usr/bin/env python
#
#       driverscan.py
#       
#       Copyright 2009 Andreas Schuster <a.schuster@yendor.net>
#       
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#       
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#       
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.

"""
@author:       Andreas Schuster
@license:      GNU General Public License 2.0 or later
@contact:      a.schuster@forensikblog.de
@organization: http://computer.forensikblog.de/en/
"""

from forensics.object2 import *
from forensics.object import *
from vutils import *
from forensics.win32.scan2 import *
from forensics.win32.meta_info import *

driver_types = {
    '_DRIVER_OBJECT' : [ 0xa8, {
        'Type' : [ 0x0, ['unsigned short']],
        'Size' : [ 0x2, ['unsigned short']],
        'DeviceObject' : [ 0x4, ['pointer', ['_DEVICE_OBJECT']]],
        'Flags' : [ 0x8, ['unsigned long']],
        'DriverStart' : [ 0xc, ['pointer']],
        'DriverSize' : [ 0x10, ['unsigned long']],
        'DriverSection' : [ 0x14, ['pointer']],
        'DriverExtension' : [ 0x18, ['pointer', ['_DRIVER_EXTENSION']]],
        'DriverName' : [ 0x1c, ['_UNICODE_STRING']],
        'HardwareDatabase' : [ 0x24, ['pointer', ['_UNICODE_STRING']]],
        'FastIoDispatch' : [ 0x28, ['pointer', ['_FAST_IO_DISPATCH']]],
        'DriverInit' : [ 0x2c, ['pointer']],
        'DriverStartIo' : [ 0x30, ['pointer']],
        'DriverUnload' : [ 0x34, ['pointer']],
        'MajorFunction' : [ 0x38, ['array', 28, ['pointer']]],
    } ],
    '_DRIVER_EXTENSION' : [ 0x1c, {
        'DriverObject' : [ 0x0, ['pointer', ['_DRIVER_OBJECT']]],
        'AddDevice' : [ 0x4, ['pointer']],
        'Count' : [ 0x8, ['unsigned long']],
        'ServiceKeyName' : [ 0xc, ['_UNICODE_STRING']],
        'ClientDriverExtension' : [ 0x14, ['pointer', ['_IO_CLIENT_EXTENSION']]],
        'FsFilterCallbacks' : [ 0x18, ['pointer', ['_FS_FILTER_CALLBACKS']]],
    } ],
    '_OBJECT_NAME_INFO' : [ 0xc, {
        'Directory' : [ 0x0, ['pointer', ['_OBJECT_DIRECTORY']]],
        'Name' : [ 0x04, ['_UNICODE_STRING']],
    } ],  
    '_OBJECT_HEADER' : [ 0x18, {
        'PointerCount' : [ 0x0, ['int']],
        'HandleCount' : [ 0x4, ['int']],
        'Type' : [ 0x8, ['pointer', ['_OBJECT_TYPE']]],
        'NameInfoOffset' : [ 0x0c, ['unsigned char']],
        'HandleInfoOffset' : [ 0xd, ['unsigned char']],    
        'QuotaInfoOffset' : [ 0xe, ['unsigned char']],
        'Flags' : [ 0xf, ['unsigned char']],
        'ObjectCreateInfo' : [ 0x10, ['pointer']],
        'SecurityDescriptor' : [ 0x14, ['pointer']],
    } ],
}


class PoolScanDriver(GenMemScanObject):
    """ Scan for pool objects """
    def __init__(self,addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x44\x72\x69\xf6"
        self.pool_size = 0xf8
        
    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.kas = meta_info.KernelAddressSpace
            # add constraints
            self.add_constraint(self.check_pooltype_nonpaged)
            self.add_constraint(self.check_poolindex_zero)
            self.add_constraint(self.check_blocksize_equal)

        def object_offset(self,found):
            return found - 4 + obj_size(self.data_types, \
                '_POOL_HEADER')
                
        def object_action(self,buff,object_offset):
            AllocSize = self.get_poolsize(buff, object_offset-4)
            SizeOfDriverObj = obj_size(self.data_types, '_DRIVER_OBJECT') 
            SizeOfDriverExt = obj_size(self.data_types, '_DRIVER_EXTENSION')
            SizeOfObjectHeader = obj_size(self.data_types, \
                '_OBJECT_HEADER')
            if SizeOfDriverObj+SizeOfDriverExt+SizeOfObjectHeader > AllocSize:
                return False

            # build structure from higher to lower addresses
            StartOfDriverExt = object_offset - 8 + AllocSize - \
                SizeOfDriverExt - 4
            StartOfDriverObj = StartOfDriverExt - SizeOfDriverObj
            
            DriverName = read_unicode_string_buf(buff, self.kas, self.data_types, \
                ['_DRIVER_OBJECT', 'DriverName'], StartOfDriverObj)
            DriverStart = read_obj_from_buf(buff, self.data_types, \
                ['_DRIVER_OBJECT', 'DriverStart'], StartOfDriverObj)
            DriverSize = read_obj_from_buf(buff, self.data_types, \
                ['_DRIVER_OBJECT', 'DriverSize'], StartOfDriverObj)   
            
            ServiceKey = read_unicode_string_buf(buff, self.kas, self.data_types, \
                ['_DRIVER_EXTENSION', 'ServiceKeyName'], StartOfDriverExt)

            StartOfObjectHeader = StartOfDriverObj - SizeOfObjectHeader
            ObjType = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'Type'], \
                StartOfObjectHeader)
            # suppress destructed objects
            #if (ObjType == 0xbad0b0b0):
                #return False
            Pointers = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'PointerCount'], \
                StartOfObjectHeader)
            Handles = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'HandleCount'], \
                StartOfObjectHeader)
            OfsName = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'NameInfoOffset'], \
                StartOfObjectHeader)
                
            # try to work around some rootkits
            gap = StartOfObjectHeader-object_offset
            if ((OfsName == 0) and (gap >= 0x10)):
                OfsName = gap
                
            if OfsName > 0:
                StartOfName = StartOfObjectHeader - OfsName
                Name = read_unicode_string_buf(buff, self.kas, self.data_types, \
                    ['_OBJECT_NAME_INFO', 'Name'], StartOfName) 
                if (Name == None):
                    Name = ''
            else:
                Name = '' 

            address = self.as_offset + object_offset
            
            print "0x%08x 0x%08x %4d %4d 0x%08x %6d %-20s %-12s %s" % \
                (address, ObjType, Pointers, Handles, \
                DriverStart, DriverSize, ServiceKey, Name, DriverName)

class driverscan(forensics.commands.command):

    # Declare meta information associated with this plugin

    meta_info = forensics.commands.command.meta_info
    meta_info['author'] = 'Andreas Schuster'
    meta_info['copyright'] = 'Copyright (c) 2009 Andreas Schuster'
    meta_info['contact'] = 'a.schuster@forensikblog.de'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://computer.forensikblog.de/en/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '0.2'
    
    def help(self):
        return  "Scan for driver objects"   
        
    def execute(self):
        op = self.op
        opts = self.opts
        
        (addr_space, symtab, types) = load_and_identify_image(op, opts)
        set_kas(addr_space)
                
        # merge type information and make it globally accessible
        types.update(driver_types)
        set_datatypes(types)
                     
        try:
            flat_addr_space = FileAddressSpace(opts.filename, fast=True)
        except:
            op.error("Unable to open image file %s" %(opts.filename))
                     
        search_addr_space = find_addr_space(flat_addr_space, types)
        scanners = []
        scanners.append(PoolScanDriver(search_addr_space))
        
        print "%-10s %-10s %4s %4s %-10s %6s %-20s %s" % \
            ('Phys.Addr.', 'Obj Type', '#Ptr', '#Hnd', \
            'Start', 'Size', 'Service key', 'Name')
        scan_addr_space(search_addr_space, scanners)        
