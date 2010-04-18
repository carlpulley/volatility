#!/usr/bin/env python
#
#       fileobjscan.py
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

extra_types = {
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
    '_OWNER_INFO': [ 0x8, {
        'Owner' : [ 0x0, ['pointer', ['_EPROCESS']]],
        'HandleCount' : [ 0x4, ['unsigned long']],
    } ],
    '_OBJECT_HANDLE_DB' : [ 0x8, {
        'HandleDb' : [ 0x0, ['pointer']],
        'Count' : [ 0x4, ['unsigned long']],
    } ],
    '_OBJECT_HANDLE_DB_ENTRY' : [ 0x8, {
        'HandleCount' : [ 0x0, ['unsigned long']],
        'Owner' : [ 0x4, ['pointer', ['_EPROCESS']]],
    } ],
    '_FILE_OBJECT' : [ 0x70, {
        'Type' : [ 0x0, ['unsigned short']],
        'Size' : [ 0x2, ['unsigned short']],
        'DeviceObject' : [ 0x4, ['pointer', ['_DEVICE_OBJECT']]],
        'Vpb' : [ 0x8, ['pointer', ['_VPB']]],
        'FsContext' : [ 0xc, ['pointer']],
        'FsContext2' : [ 0x10, ['pointer']],      
        'SectionObjectPointer' : [ 0x14, ['pointer', ['_SECTION_OBJECT_POINTERS']]],
        'PrivateCacheMap' : [ 0x18, ['pointer']],
        'FinalStatus' : [ 0x1c, ['unsigned long']],
        'RelatedFileObject' : [ 0x20, ['pointer', ['_FILE_OBJECT']]],
        'LockOperation' : [ 0x24, ['unsigned char']],
        'DeletePending' : [ 0x25, ['unsigned char']],
        'ReadAccess' : [ 0x26, ['unsigned char']],
        'WriteAccess' : [ 0x27, ['unsigned char']],
        'DeleteAccess' : [ 0x28, ['unsigned char']],
        'SharedRead' : [ 0x29, ['unsigned char']],
        'SharedWrite' : [ 0x2a, ['unsigned char']],
        'SharedDelete' : [ 0x2b, ['unsigned char']],
        'Flags' : [ 0x2c, ['unsigned long']],
        'FileName' : [ 0x30, ['_UNICODE_STRING']],
        'CurrentByteOffset' : [ 0x38, ['_LARGE_INTEGER']],
        'Waiters' : [ 0x40, ['unsigned long']],
        'Busy' : [ 0x44, ['unsigned long']],
        'LastLock' : [ 0x48, ['pointer']],
        'Lock' : [ 0x4c, ['_KEVENT']],
        'Event' : [ 0x5c, ['_KEVENT']],
        'CompletionContext' : [ 0x6c, ['pointer', ['_IO_COMPLETION_CONTEXT']]],
    } ],
    '_SECTION_OBJECT_POINTERS' : [ 0xc, {
        'DataSectionObject' : [ 0x0, ['pointer', ['void']]],
        'SharedCacheMap' : [ 0x4, ['pointer', ['void']]],
        'ImageSectionObject' : [ 0x8, ['pointer', ['void']]]
    } ],
    '_SHARED_CACHE_MAP' : [ 0x130, {
        'NodeTypeCode' : [ 0x00, ['short']],
        'NodeByteSize'     : [ 0x02, ['short']],
        'OpenCount'        : [ 0x04, ['unsigned int']],
        'FileSize'         : [ 0x08, ['_LARGE_INTEGER']],
        'BcbList'          : [ 0x10, ['_LIST_ENTRY']],
        'SectionSize'      : [ 0x18, ['_LARGE_INTEGER']],
        'ValidDataLength'  : [ 0x20, ['_LARGE_INTEGER']],
        'ValidDataGoal'    : [ 0x28, ['_LARGE_INTEGER']],
        'InitialVacbs'     : [ 0x30, ['array', 4, ['pointer', ['_VACB']]]],
        'Vacbs'            : [ 0x40, ['pointer', ['pointer', ['_VACB']]]],
        'FileObject'       : [ 0x44, ['pointer', ['_FILE_OBJECT']]],
        'ActiveVacb'       : [ 0x48, ['pointer', ['_VACB']]],
        'NeedToZero'       : [ 0x4c, ['pointer', ['void']]],
        'ActivePage'       : [ 0x50, ['unsigned int']],
        'NeedToZeroPage'   : [ 0x54, ['unsigned int']],
        'ActiveVacbSpinLock' : [ 0x58, ['unsigned int']],
        'VacbActiveCount'  : [ 0x5c, ['unsigned int']],
        'DirtyPages'       : [ 0x60, ['unsigned int']],
        'SharedCacheMapLinks' : [ 0x64, ['_LIST_ENTRY']],
        'Flags'            : [ 0x6c, ['unsigned int']],
        'Status'           : [ 0x70, ['int']],
        'Mbcb'             : [ 0x74, ['pointer', ['_MBCB']]],
        'Section'          : [ 0x78, ['pointer', ['void']]],
        'CreateEvent'      : [ 0x7c, ['pointer', ['_KEVENT']]],
        'WaitOnActiveCount' : [ 0x80, ['pointer', ['_KEVENT']]],
        'PagesToWrite'     : [ 0x84, ['unsigned int']],
        'BeyondLastFlush'  : [ 0x88, ['long long']],
        'Callbacks'        : [ 0x90, ['pointer', ['_CACHE_MANAGER_CALLBACKS']]],
        'LazyWriteContext' : [ 0x94, ['pointer', ['void']]],
        'PrivateList'      : [ 0x98, ['_LIST_ENTRY']],
        'LogHandle'        : [ 0xa0, ['pointer', ['void']]],
        'FlushToLsnRoutine' : [ 0xa4, ['pointer', ['void']]],
        'DirtyPageThreshold' : [ 0xa8, ['unsigned int']],
        'LazyWritePassCount' : [ 0xac, ['unsigned int']],
        'UninitializeEvent' : [ 0xb0, ['pointer', ['_CACHE_UNINITIALIZE_EVENT']]],
        'NeedToZeroVacb'   : [ 0xb4, ['pointer', ['_VACB']]],
        'BcbSpinLock'      : [ 0xb8, ['unsigned int']],
        'Reserved'         : [ 0xbc, ['pointer', ['void']]],
        'Event'            : [ 0xc0, ['_KEVENT']],
        'VacbPushLock'     : [ 0xd0, ['_EX_PUSH_LOCK']],
        'PrivateCacheMap'  : [ 0xd8, ['_PRIVATE_CACHE_MAP']],
    } ],
    '_VACB' : [ 0x18, {
        'BaseAddress' : [ 0x0, ['pointer', ['void']]],
        'SharedCacheMap' : [ 0x4, ['pointer', ['_SHARED_CACHE_MAP']]],
        'Overlay' : [ 0x8, ['__unnamed']],
        'LruList' : [ 0x10, ['_LIST_ENTRY']],
    } ],
}

class PoolScanFile(GenMemScanObject):
    """ Scan for pool objects """
    def __init__(self,addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x46\x69\x6c\xe5"
        self.pool_size = 0x98

    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.kas = meta_info.KernelAddressSpace
            # add constraints
            self.add_constraint(self.check_pooltype_nonpaged)
            self.add_constraint(self.check_poolindex_zero)
            self.add_constraint(self.check_blocksize_geq)

        def object_offset(self,found):
            return found - 4 + obj_size(self.data_types, \
                '_POOL_HEADER')
                
        def object_action(self,buff,object_offset):
            AllocSize = self.get_poolsize(buff, object_offset-4)
         
            # build structure from higher to lower addresses            
            SizeOfFile = obj_size(self.data_types, '_FILE_OBJECT')
            StartOfFile = object_offset - 8 + AllocSize - SizeOfFile
            Name = read_unicode_string_buf(buff, self.kas, self.data_types, \
                ['_FILE_OBJECT', 'FileName'], StartOfFile)
            # unclutter the output
            if ((Name == None) or (Name == '')):
                return False
                        
            def _check_access(self,buff,member,indicator,offset):
                if (read_obj_from_buf(buff, self.data_types, \
                    ['_FILE_OBJECT', member], StartOfFile) > 0):
                        return indicator
                else:
                    return '-'
                
            AccessStr =  _check_access(self, buff, \
                'ReadAccess', 'R', StartOfFile)
            AccessStr += _check_access(self, buff, \
                'WriteAccess', 'W', StartOfFile)
            AccessStr += _check_access(self, buff, \
                'DeleteAccess', 'D', StartOfFile)
            AccessStr += _check_access(self, buff, \
                'SharedRead', 'r', StartOfFile)
            AccessStr += _check_access(self, buff, \
                'SharedWrite', 'w', StartOfFile)
            AccessStr += _check_access(self, buff, \
                'SharedDelete', 'd', StartOfFile)
     

            SizeOfObjectHeader = obj_size(self.data_types, '_OBJECT_HEADER')            
            StartOfObjectHeader = StartOfFile - SizeOfObjectHeader
            ObjType = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'Type'], \
                StartOfObjectHeader)
            if ((ObjType == None) or (ObjType == 0xbad0b0b0)):
                return False
            Pointers = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'PointerCount'], \
                StartOfObjectHeader)
            Handles = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'HandleCount'], \
                StartOfObjectHeader) 
            Flags = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'Flags'], \
                StartOfObjectHeader)
            HandleInfoOffset = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'HandleInfoOffset'], \
                StartOfObjectHeader)
                
            address = self.as_offset + object_offset + 0x20 # Bug fix
    
            Owners = []
            if (HandleInfoOffset > 0):
                # object has _OBJECT_HANDLE_DB
                SizeOfHandleInfo = obj_size(self.data_types, '_OBJECT_HANDLE_DB')
                StartOfHandleInfo = StartOfObjectHeader-HandleInfoOffset            

                if (Flags & 0x40):
                    # single owner entry
                    EProcess = read_obj_from_buf(buff, self.data_types, \
                        ['_OWNER_INFO', 'Owner'], \
                        StartOfHandleInfo)
                    HandleCnt = read_obj_from_buf(buff, self.data_types, \
                        ['_OWNER_INFO', 'HandleCount'], \
                        StartOfHandleInfo)
                    Owners.append((EProcess, HandleCnt))
                else:
                    # list of owner entries
                    count = read_obj_from_buf(buff, self.data_types, \
                        ['_OBJECT_HANDLE_DB', 'Count'], \
                        StartOfHandleInfo)
                    StartOfHandleDb = read_obj_from_buf(buff, self.data_types, \
                        ['_OBJECT_HANDLE_DB', 'HandleDb'], \
                        StartOfHandleInfo)
                    SizeOfHandleDbEntry = obj_size(self.data_types, \
                        '_OBJECT_HANDLE_DB_ENTRY')
                    for i in range(count):
                        StartOfHandleDbEntry = StartOfHandleDb + \
                            (i * SizeOfHandleDbEntry)
                        EProcess = read_obj(self.kas, self.data_types, \
                            ['_OBJECT_HANDLE_DB_ENTRY', 'Owner'], \
                            StartOfHandleDbEntry)
                        HandleCnt = read_obj(self.kas, self.data_types, \
                            ['_OBJECT_HANDLE_DB_ENTRY', 'Owner'], \
                            StartOfHandleDbEntry)
                        Owners.append((EProcess, HandleCnt))
                    

            for (EProcess, HandleCnt) in Owners:
                if ((EProcess >= 0x80000000) and (EProcess != 0xbad0b0b0)):
                    PID = read_obj(self.kas, self.data_types, \
                        ['_EPROCESS', 'UniqueProcessId'], \
                        EProcess)
                    if PID == None:
                        PID = 0
                else:
                    PID = 0

                    
                print "0x%08x 0x%08x %4d %4d %6s 0x%08x %4d %s" % \
                    (address, ObjType, Pointers, Handles, AccessStr, \
                        EProcess, PID, Name)


class fileobjscan(forensics.commands.command):

    # Declare meta information associated with this plugin

    meta_info = forensics.commands.command.meta_info
    meta_info['author'] = 'Andreas Schuster'
    meta_info['copyright'] = 'Copyright (c) 2009 Andreas Schuster'
    meta_info['contact'] = 'a.schuster@forensikblog.de'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://computer.forensikblog.de/en/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '0.3'

    def help(self):
        return  "Scan for file objects"

    def execute(self):
        op = self.op
        opts = self.opts
           
        (addr_space, symtab, types) = load_and_identify_image(op, opts)
        set_kas(addr_space)
                
        # merge type information and make it globally accessible
        types.update(extra_types)
        set_datatypes(types)
                     
        try:
            flat_addr_space = FileAddressSpace(opts.filename, fast=True)
        except:
            op.error("Unable to open image file %s" %(filename))
                     
        search_addr_space = find_addr_space(flat_addr_space, types)
        scanners = []
        scanners.append((PoolScanFile(search_addr_space)))
        
        print "%-10s %-10s %4s %4s %6s %-10s %4s %s" % \
            ('Phys.Addr.', 'Obj Type', '#Ptr', '#Hnd', 'Access',\
            'EProcess', 'PID', 'Name')
        scan_addr_space(search_addr_space, scanners)
