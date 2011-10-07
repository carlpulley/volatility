#!/usr/bin/env python
#
# exportfile.py
# Copyright (C) 2010 Carl Pulley <c.j.pulley@hud.ac.uk>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
This plugin implements the exporting and saving of _FILE_OBJECT's

@author:       Carl Pulley
@license:      GNU General Public License 2.0 or later
@contact:      c.j.pulley@hud.ac.uk
@organization: University of Huddersfield
"""

import re
import commands
import os.path
import volatility.utils as utils
import volatility.obj as obj
import volatility.win32.tasks as tasks
import volatility.plugins.filescan as filescan

class ExportFile(filescan.FileScan):
	"""
	Given a PID or _EPROCESS, and (optionally) a _FILE_OBJECT, extract the associated file(s) from memory.
	
	Pages that can not be retrieved from memory are saved as pages filled in a given fill character.
	
	Exported files are written to a user-defined dump directory. Contiguous retrievable pages are written
	to a file named using the retrieved virtual addresses. In addition, a "this" file is created - this is 
	an aggregation of the retrieved pages with non-retrievable pages substitued by fill-character pages.
	All exported files are placed into a common directory whose name and path agree with that located in
	_FILE_OBJECT.
	
	This plugin is particularly useful when one expects memory (that holds the file's shared cache pages) to be 
	fragmented, and so linear carving techniques (e.g. using scalpel or foremost) might be expected to fail.
	
	EXAMPLE:
	
	...TODO...
	
	REFERENCES:
	[1] Information on accessing shared cache maps etc.:
	    Russinovich, M., Solomon, D.A. & Ionescu, A., 2009. Windows Internals: Including Windows Server 2008 and Windows Vista, Fifth Edition (Pro Developer) 5th ed. Microsoft Press.
	[2] Information on mapping _FILE_OBJECT's to _EPROCESS:
	    http://computer.forensikblog.de/en/2009/04/linking_file_objects_to_processes.html (accessed 6/Oct/2011)
	[3] OSR Online article: Finding File Contents in Memory
	    http://www.osronline.com/article.cfm?article=280 (accessed 7/Oct/2011)
	"""

	meta_info = dict(
		author = 'Carl Pulley',
		copyright = 'Copyright (c) 2010 Carl Pulley',
		contact = 'c.j.pulley@hud.ac.uk',
		license = 'GNU General Public License 2.0 or later',
		url = 'http://compeng.hud.ac.uk/scomcjp',
		os = ['WinXPSP2x86', 'WinXPSP3x86'],
		version = '1.0',
		)

	def __init__(self, config, *args):
		filescan.FileScan.__init__(self, config, *args)
		config.add_option("fill", default = 0, type = 'int', action = 'store', help = "Fill character for padding out missing pages in shared file object caches")
		config.add_option("dir", short_option = 'D', default = ".", type = 'str', action = 'store', help = "Directory in which to save exported files")
		config.add_option("pid", type = 'int', action = 'store', help = "Extract all associated _FILE_OBJECT's from a PID")
		config.add_option("eproc", type = 'int', action = 'store', help = "Extract all associated _FILE_OBJECT's from a _EPROCESS offset (physical address)")
		config.add_option("fobj", type = 'int', action = 'store', help = "Extract a given _FILE_OBJECT offset (physical address)")

	# BUG: filescan plugin appears to calculate _FILE_OBJECT physical addresses which need #18 bytes adding to them?
	# TODO: extract and collate data from private cache maps
	def calculate(self):
		self.kernel_address_space = utils.load_as(self._config)
		self.flat_address_space = utils.load_as(self._config, astype = 'physical')
		if not(bool(self._config.pid) ^ bool(self._config.eproc)):
			if not(bool(self._config.pid) or bool(self._config.eproc)):
				raise Exception("ERROR: exactly one of the options --pid or --eproc *MUST* be specified (you have not specified _any_ of these options)")
			else:
				raise Exception("ERROR: exactly one of the options --pid or --eproc *MUST* be specified (you have specified _both_ of these options)")
		if self._config.pid:
			eproc_matches = [ eproc for eproc in tasks.pslist(self.kernel_address_space) if eproc.UniqueProcessId == self._config.pid ]
			if len(eproc_matches) != 1:
				raise Exception("ERROR: -pid needs to take a *VALID* PID argument (could not find PID {0} in the process listing for this memory image)".format(self._config.pid))
			return self.dump_from_eproc(eproc_matches[0])
		else:
			return self.dump_from_eproc(obj.Object("_EPROCESS", offset = self._config.eproc, vm = self.flat_address_space))

	def dump_from_eproc(self, eproc):
		self.process_address_space = eproc.get_process_address_space()
		if self._config.fobj:
			return filter(None, [ self.dump_file_object(obj.Object("_FILE_OBJECT", offset = self._config.fobj, vm = self.flat_address_space)) ])
		else:
			# FIXME: need to restrict _FILE_OBJECT's to the given _EPROCESS
			return filter(None, [ self.dump_file_object(file_obj) for (object_obj, file_obj, name) in filescan.FileScan.calculate(self) if True ])

	def render_text(self, outfd, data):
		for file_name, file_size, file_object in data:
			for vacb, section in file_object:
				self.dump_section(outfd, vacb.BaseAddress, file_size, section, file_name)
    
	def render_sql(self, outfd, data):
		raise Exception("TODO: not implemented yet!")

	KB = 0x400
	_1KB = KB
	MB = _1KB**2
	_1MB = MB
	GB = _1KB**3
	_1GB = GB
	
	def read_large_integer(self, large_integer):
		return large_integer.HighPart.v() * pow(2, 4 *8) + large_integer.LowPart.v()

	def vacb_node_size(self, file_size):
		if file_size < self._1MB:
			return 1
		elif file_size < 32*self.MB:
			return 4
		else:
			return 128

	def read_vacbs_from_cache_map(self, shared_cache_map, node_size=1):
		if node_size == 1:
			return [ (shared_cache_map.Vacbs, 0) ]
		elif node_size == 4:
			return [ (shared_cache_map.Vacbs + node_size*index, index) for index in range(0, node_size) ]
		elif node_size == 128:
			# TODO: calculate vacb tree depth
			# TODO: traverse vacb tree and grab vacb addresses
			raise Exception("TODO: not implemented yet!")
		else:
			raise Exception("ERROR: {0} is an invalid node size - nodes may only be 1, 4 or 128 element array(s)".format(node_size))

	def dump_file_object(self, file_object):
		# TODO: when writing section pages, need to detect overwrites and compare for sanities sake!?
		file_name = self.parse_string(file_object.FileName)
		if file_name == None:
			raise Exception("ERROR: expected file name to be non-null!")
		classify = [ False, False, False ] # [ DataSectionObject != None, SharedCacheMap != None, ImageSectionObject != None ]
		section_object_ptr = obj.Object('_SECTION_OBJECT_POINTERS', offset = file_object.SectionObjectPointer, vm = self.process_address_space)
		shared_cache_map = obj.Object('_SHARED_CACHE_MAP', offset = section_object_ptr.SharedCacheMap, vm = self.process_address_space)
		if section_object_ptr.DataSectionObject != 0 and section_object_ptr.DataSectionObject != None:
			classify[0] = True
			print "TODO: dump DataSectionObject _CONTROL_AREA"
		if section_object_ptr.ImageSectionObject != 0 and section_object_ptr.ImageSectionObject != None:
			classify[2] = True
			print "TODO: dump ImageSectionObject _CONTROL_AREA"
		if shared_cache_map != 0 and shared_cache_map != None:
			classify[1] = True
			file_size = self.read_large_integer(shared_cache_map.FileSize)
			return (file_name, file_size, [ (vacb, section) for (vacb, section) in self.read_vacbs_from_cache_map(shared_cache_map, self.vacb_node_size(file_size)) if vacb != 0 and vacb != None ])
		if not(classify[0]) and not(classify[2]):
			print "WARNING:", file_name
			print "  has no _CONTROL_AREA object (as no DataSectionObject and no ImageSectionObject exists for the file object's _SECTION_OBJECT_POINTERS), and one should exist!"

	# FIXME: finish porting the following code!
	def dump_data(self, outfd, data, addr, start, end, section, base_dir):
		#with open("%s/cache.0x%02X-0x%02X.dmp"%(base_dir, section*(256*KB) + start*(4*KB), section*(256*KB) + end*(4*KB) - 1), 'wb') as fobj:
		#	fobj.write(data)
		header_str = "File Offset Range: 0x%02X -> 0x%02X"%(section*(256*self.KB) + start*(4*self.KB), section*(256*self.KB) + end*(4*self.KB) - 1)
		outfd.write(header_str)
		outfd.write("\n")
		outfd.write("*"*len(header_str))
		outfd.write("\n")
		outfd.write(data)
		#db(addr)

	def dump_section(self, outfd, addr, size, section, file_name):
		max_page = (size/(4*self.KB)) + 1
		section_data = ""
		result = ""
		padding = ""
		fill_char = self._config.fill
		base_dir = re.sub(r'[\\:]', '/', self._config.dir + "/" + file_name)
		#if not os.path.exists(base_dir):
		#	commands.getoutput("mkdir -p %s"%re.escape(base_dir))
		last_page = 0
		for page in range(0, max_page):
			if self.process_address_space.is_valid_address(addr + page*(4*self.KB)): # FIXME
				if padding != "":
					section_data += padding
				padding = ""
				if page > 0 and result == "":
					last_page = page
				result += self.process_address_space.read(addr + page*(4*self.KB), (4*self.KB)) # FIXME:
			else:
				padding += fill_char*(4*self.KB)
				if result != "":
					section_data += result
					self.dump_data(outfd, result, addr + last_page*(4*self.KB), last_page, page, section, base_dir)
				result = ""
		if padding != "":
			section_data += padding
		if result != "":
			section_data += result
			self.dump_data(outfd, result, addr + last_page*(4*self.KB), last_page, max_page, section, base_dir)
		outfd.write(section_data)


#def my_read_time(addr_space, types, member_list, vaddr):
#    (offset, _) = get_obj_offset(types, member_list)
#		
#    low_time  = read_obj(addr_space, types, ['_KSYSTEM_TIME', 'LowPart'], vaddr+offset)
#    high_time = read_obj(addr_space, types, ['_KSYSTEM_TIME', 'High1Time'], vaddr+offset)
#    
#    if low_time == None or high_time == None:
#        return None
#    
#    return (high_time << 32) | low_time
#
#def size_str(size):
#    size_str = size
#    units = ""
#    if size % _1MB == size:
#        size_str = size/_1KB
#        units = "K"
#    elif size % _1GB == size:
#        size_str = size/_1MB
#        units = "M"
#    else:
#        size_str = size/_1GB
#        units = "G"
#    return "%d%c"%(size_str, units)
    