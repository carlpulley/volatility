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

"""
Modified by Michael Ligh (michael.ligh@mnin.org) 
This plugin named "driverirp.py" requires driverscan.py by Andreas Schuster 
(see the above information) and re-uses a large amount of the original code. 
"""

from forensics.object2 import *
from forensics.win32.scan2 import *
from driverscan import *

from forensics.win32.modules import modules_list
from forensics.win32.executable import rebuild_exe_dsk,rebuild_exe_mem

mj = ['IRP_MJ_CREATE',
      'IRP_MJ_CREATE_NAMED_PIPE',
      'IRP_MJ_CLOSE',
      'IRP_MJ_READ',
      'IRP_MJ_WRITE',
      'IRP_MJ_QUERY_INFORMATION',
      'IRP_MJ_SET_INFORMATION',
      'IRP_MJ_QUERY_EA',
      'IRP_MJ_SET_EA',
      'IRP_MJ_FLUSH_BUFFERS',
      'IRP_MJ_QUERY_VOLUME_INFORMATION',
      'IRP_MJ_SET_VOLUME_INFORMATION',
      'IRP_MJ_DIRECTORY_CONTROL',
      'IRP_MJ_FILE_SYSTEM_CONTROL',
      'IRP_MJ_DEVICE_CONTROL',
      'IRP_MJ_INTERNAL_DEVICE_CONTROL',
      'IRP_MJ_SHUTDOWN',
      'IRP_MJ_LOCK_CONTROL',
      'IRP_MJ_CLEANUP',
      'IRP_MJ_CREATE_MAILSLOT',
      'IRP_MJ_QUERY_SECURITY',
      'IRP_MJ_SET_SECURITY',
      'IRP_MJ_POWER',
      'IRP_MJ_SYSTEM_CONTROL',
      'IRP_MJ_DEVICE_CHANGE',
      'IRP_MJ_QUERY_QUOTA',
      'IRP_MJ_SET_QUOTA',
      'IRP_MJ_PNP']
      
def lookup_module_by_address(loaded_modules, MajorFunction):
    dest_name = ""
    for mod in loaded_modules:
        if ( (MajorFunction > mod.mod_base) and (MajorFunction < (mod.mod_base + mod.mod_size)) ):
            dest_name = mod.mod_name
    return dest_name
      
# This is from BDG's moddump.py
def find_space(addr_space, types, symtab, addr):
  # short circuit if given one works
  if addr_space.is_valid_address(addr): return addr_space

  pslist = process_list(addr_space, types, symtab)
  for p in pslist:
      dtb = process_dtb(addr_space, types, p)
      space = create_addr_space(addr_space, dtb)
      if space.is_valid_address(addr):
          return space
  return None
      
class PoolScanDriverIRP(PoolScanDriver):
  def __init__(self,addr_space, loaded_modules):
      GenMemScanObject.__init__(self, addr_space)
      self.pool_tag = "\x44\x72\x69\xf6"
      self.pool_size = 0xf8
      self.loaded_modules = loaded_modules

  class Scan(PoolScanDriver.Scan):
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

          IRP_MJ_MAXIMUM_FUNCTION = 28

          (offset, current_type) = get_obj_offset(self.data_types,['_DRIVER_OBJECT', 'MajorFunction'])
          voffset = StartOfDriverObj + offset

          for code in range(0, IRP_MJ_MAXIMUM_FUNCTION):
              entry = voffset + code * 4
              try:
                  (MajorFunction, ) = struct.unpack('=L', buff[entry:entry+4])
              except:
                  print "[%d] ERROR" % code
                  continue
                  
              dest_module = lookup_module_by_address(self.outer.loaded_modules, MajorFunction)
              if (dest_module == "") or (dest_module == None):
                  combo = "0x%x" % MajorFunction
              else:
                  combo = "%s!0x%x" % (dest_module, MajorFunction)
              
              print "\t[%d] %-32s 0x%-12x %s" % (code, mj[code], MajorFunction, combo)

class module: 
    def __init__(self, mod_name=None, mod_base=None, mod_size=None):
        self.mod_name = mod_name
        self.mod_base = mod_base
        self.mod_size = mod_size

class driverirp(forensics.commands.command):
    
    def help(self):
        return  "[VAP] Print driver IRP function addresses"   
        
    def execute(self):
        op = self.op
        opts = self.opts

        (addr_space, symtab, types) = load_and_identify_image(op, opts)
        
        rebuild_exe = rebuild_exe_mem
        
        # get a list of the loaded modules (this is for resolving imports, *not* for finding hidden driver objects)
        modlist = modules_list(addr_space, types, symtab)
        theProfile = Profile()
        loaded_modules = []

        for m in modlist:
            mod = Object("_LDR_MODULE", m, addr_space, profile=theProfile)

            lm = module(mod.ModuleName, mod.BaseAddress.v(), mod.SizeOfImage)
            loaded_modules.append(lm)
        
        print "Recorded %d loaded modules" % len(loaded_modules)
        
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
        scanners.append(PoolScanDriverIRP(search_addr_space, loaded_modules))

        print "%-10s %-10s %4s %4s %-10s %6s %-20s %s" % \
            ('Phys.Addr.', 'Obj Type', '#Ptr', '#Hnd', \
            'Start', 'Size', 'Service key', 'Name')
            
        scan_addr_space(search_addr_space, scanners)      
