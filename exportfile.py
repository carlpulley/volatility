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
import math
import volatility.utils as utils
import volatility.obj as obj
import volatility.win32.tasks as tasks
import volatility.debug as debug
import volatility.plugins.filescan as filescan

class ExportFile(filescan.FileScan):
	"""
	Given a PID or _EPROCESS, and (optionally) a _FILE_OBJECT, extract the 
	associated (or given) _FILE_OBJECT's from memory.
	
	Pages that can not be retrieved from memory are saved as pages filled in 
	with a given fill character (--fill).
	
	Exported files are written to a user-defined dump directory (--dir). 
	Contiguous retrievable pages are written to a file named using the 
	retrieved virtual addresses. In addition, a "this" file is created (with 
	the correct file size!) - this is an aggregation of the retrieved pages 
	with non-retrievable pages substitued by fill-character pages (--fill).
	All exported files are placed into a common directory (--dir) whose name 
	and path agree with that located in _FILE_OBJECT (modulo a unix/linux path 
	naming convention).
	
	This plugin is particularly useful when one expects memory (that holds the 
	file's shared cache pages) to be fragmented, and so, linear carving 
	techniques (e.g. using scalpel or foremost) might be expected to fail. See 
	reference [5] (below) for more information regarding some of the benefits 
	of accessing files via the _FILE_OBJECT data structure.
	
	EXAMPLE 1: Memory Mapped
	
	...TODO...
	
	EXAMPLE 2: Shared Cache Map
	
	...TODO...
	
	REFERENCES:
	[1] Russinovich, M., Solomon, D.A. & Ionescu, A., 2009. Windows Internals: 
	    Including Windows Server 2008 and Windows Vista, Fifth Edition (Pro 
	    Developer) 5th ed. Microsoft Press.
	[2] Information on mapping _FILE_OBJECT's to _EPROCESS (accessed 6/Oct/2011):
	    http://computer.forensikblog.de/en/2009/04/linking_file_objects_to_processes.html
	[3] OSR Online article: Finding File Contents in Memory (accessed 7/Oct/2011):
	    http://www.osronline.com/article.cfm?article=280
	[4] Extracting Event Logs or Other Memory Mapped Files from Memory Dumps by 
	    J. McCash (accessed 7/Oct/2011):
	    http://computer-forensics.sans.org/blog/2011/02/01/digital-forensics-extracting-event-logs-memory-mapped-files-memory-dumps
	[5] Physical Memory Forensics for Files and Cache by J. Butler and J. 
	    Murdock (accessed 8/Oct/2011):
	    https://media.blackhat.com/bh-us-11/Butler/BH_US_11_ButlerMurdock_Physical_Memory_Forensics-WP.pdf
	[6] CodeMachine article on Prototype PTEs (accessed 8/Oct/2011):
	    http://www.codemachine.com/article_protopte.html
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
		config.add_option("fill", default = 0, type = 'int', action = 'store', help = "Fill character (in ASCII) for padding out missing pages in shared file object caches")
		config.add_option("dir", short_option = 'D', type = 'str', action = 'store', help = "Directory in which to save exported files")
		config.add_option("pid", type = 'int', action = 'store', help = "Extract all associated _FILE_OBJECT's from a PID")
		config.add_option("eproc", type = 'int', action = 'store', help = "Extract all associated _FILE_OBJECT's from a _EPROCESS offset (physical address)")
		config.add_option("fobj", type = 'int', action = 'store', help = "Extract a given _FILE_OBJECT offset (physical address)")

	def calculate(self):
		self.kernel_address_space = utils.load_as(self._config)
		self.flat_address_space = utils.load_as(self._config, astype = 'physical')
		if not(bool(self._config.pid) ^ bool(self._config.eproc)):
			if not(bool(self._config.pid) or bool(self._config.eproc)):
				debug.error("exactly *ONE* of the options --pid or --eproc must be specified (you have not specified _any_ of these options)")
			else:
				debug.error("exactly *ONE* of the options --pid or --eproc must be specified (you have specified _both_ of these options)")
		if self._config.pid:
			eproc_matches = [ eproc for eproc in tasks.pslist(self.kernel_address_space) if eproc.UniqueProcessId == self._config.pid ]
			if len(eproc_matches) != 1:
				debug.error("--pid needs to take a *VALID* PID argument (could not find PID {0} in the process listing for this memory image)".format(self._config.pid))
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
		if not(self._config.dir):
			debug.error("--dir needs to be present")
		base_dir = os.path.abspath(self._config.dir)
		for fobj_inst, file_name, file_size, file_object in data:
			# FIXME: fix this hacky way of creating directory structures
			file_name_path = re.sub(r'[\\:]', '/', base_dir + "/" + file_name)
			if not(os.path.exists(file_name_path)):
				commands.getoutput("mkdir -p {0}".format(re.escape(file_name_path)))
			for vacb, section in file_object:
				with open("{0}/this".format(file_name_path), 'wb') as fobj:
					fobj.write(self.dump_section(outfd, fobj_inst, vacb.BaseAddress, file_size, section, file_name))

	def render_sql(self, outfd, data):
		debug.error("TODO: not implemented yet!")

	KB = 0x400
	_1KB = KB
	MB = _1KB**2
	_1MB = MB
	GB = _1KB**3
	_1GB = GB

	# TODO: remove this method (we should be relying on inherited filescan version) when the upstream 
	#       filescan plugin is fixed to accomodate issue 151 on Volatility trunk (currently at 1116).
	def parse_string(self, unicode_obj):
		"""Unicode string parser"""
		## We need to do this because the unicode_obj buffer is in
		## kernel_address_space
		string_length = unicode_obj.Length
		string_offset = unicode_obj.Buffer

		string = self.kernel_address_space.read(string_offset, string_length)
		if not string:
			return ''
		return repr(string[:string_length].decode("utf16", "ignore").encode("utf8", "xmlcharrefreplace"))

	def read_large_integer(self, large_integer):
		return large_integer.HighPart.v() * pow(2, 4 *8) + large_integer.LowPart.v()

	def walk_vacb_tree(self, depth, ptr):
		if depth < 1:
			debug.error("consistency check failed (expected VACB tree to have a positive depth)")
		if depth == 1:
			return [ (obj.Object("_VACB", offset = ptr + 4*index, vm = self.process_address_space), index) for index in range(0, 128) ]
		return [ (vacb, 128*index + section) for index in range(0, 128) for (vacb, section) in self.walk_vacb_tree(depth-1, ptr+4*index) ]

	def read_vacbs_from_cache_map(self, shared_cache_map, file_size, depth = None, ptr = None):
		if file_size < self._1MB:
			return [ (shared_cache_map.InitialVacbs[index], index) for index in range(0, 4) ]
		else:
			tree_depth = math.ceil((math.ceil(math.log(file_size, 2)) - 18)/7)
			return self.walk_vacb_tree(tree_depth, shared_cache_map.Vacbs.v())

	def dump_file_object(self, file_object):
		file_name = self.parse_string(file_object.FileName)
		if file_name == None:
			debug.error("consistency check failed (expected file name to be non-null)")
		if file_name[0] == "\'":
			file_name = file_name[1:]
		if file_name[-1] == "\'":
			file_name = file_name[0:-1]
		DSO = 0 # DataSectionObject
		SCM = 1 # SharedCacheMap
		ISO = 2 # ImageSectionObject
		classify = [ False, False, False ] # [ DSO != None, SCM != None, ISO != None ]
		section_object_ptr = obj.Object('_SECTION_OBJECT_POINTERS', offset = file_object.SectionObjectPointer, vm = self.process_address_space)
		if section_object_ptr.DataSectionObject != 0 and section_object_ptr.DataSectionObject != None:
			classify[DSO] = True
		if section_object_ptr.SharedCacheMap != 0 and section_object_ptr.SharedCacheMap != None:
			classify[SCM] = True
		if section_object_ptr.ImageSectionObject != 0 and section_object_ptr.ImageSectionObject != None:
			classify[ISO] = True

		if not(classify[DSO]) and not(classify[ISO]):
			debug.error("{0}\n  has no _CONTROL_AREA object (as no DataSectionObject and no ImageSectionObject exists for the file object's _SECTION_OBJECT_POINTERS), and one should exist!".format(file_name))
		if not(classify[DSO]) and not(classify[SCM]) and not(classify[ISO]):
			debug.error("all members of _SECTION_OBJECT_POINTERS are null, and they shouldn't be!")
		if classify[SCM]:
			shared_cache_map = obj.Object('_SHARED_CACHE_MAP', offset = section_object_ptr.SharedCacheMap, vm = self.process_address_space)
			file_size = self.read_large_integer(shared_cache_map.FileSize)
			if self.read_large_integer(shared_cache_map.ValidDataLength) > file_size:
				debug.error("consistency check failed (expected ValidDataLength to be bounded by file size)")
			return (file_object, file_name, file_size, [ (vacb, section) for (vacb, section) in self.read_vacbs_from_cache_map(shared_cache_map, file_size) if vacb != 0 and vacb != None ])
		elif classify[DSO]:
			# Use System processes Page Directory to dump memory mapped drivers/modules?
			debug.error("TODO: not yet implemented")
		else:
			# Use the processes Page Directory to dump memory mapped image file?
			debug.error("TODO: not yet implemented")

	def dump_pages(self, outfd, data, addr, start, end, section, base_dir):
		with open("{0}/cache.0x{1:02X}-0x{2:02X}.dmp".format(base_dir, section*(256*self.KB) + start*(4*self.KB), section*(256*self.KB) + end*(4*self.KB) - 1), 'wb') as fobj:
			fobj.write(data)
		header_str = "Exported File Offset Range: 0x%02X -> 0x%02X"%(section*(256*self.KB) + start*(4*self.KB), section*(256*self.KB) + end*(4*self.KB) - 1)
		outfd.write(header_str)
		outfd.write("\n")
		outfd.write("*"*len(header_str))
		outfd.write("\n")

	def dump_section(self, outfd, file_object, addr, size, section, file_name):
		outfd.write("Exporting [_FILE_OBJECT @ {0:X}]:\n  {1}\n".format(file_object.v(), file_name))
		max_page = (size/(4*self.KB)) + 1
		section_data = ""
		result = ""
		padding = ""
		fill_char = chr(self._config.fill % 256)
		base_dir = re.sub(r'[\\:]', '/', self._config.dir + "/" + file_name)
		last_page = 0
		for page in range(0, max_page):
			if self.process_address_space.is_valid_address(addr + page*(4*self.KB)):
				if padding != "":
					section_data += padding
				padding = ""
				if page > 0 and result == "":
					last_page = page
				result += self.process_address_space.read(addr + page*(4*self.KB), (4*self.KB))
			else:
				padding += fill_char*(4*self.KB)
				if result != "":
					section_data += result
					self.dump_pages(outfd, result, addr + last_page*(4*self.KB), last_page, page, section, base_dir)
				result = ""
		if padding != "":
			section_data += padding
		if result != "":
			section_data += result
			self.dump_pages(outfd, result, addr + last_page*(4*self.KB), last_page, max_page, section, base_dir)
		return section_data
    