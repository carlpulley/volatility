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
import commands as exe
import os.path
import math
import struct
import volatility.utils as utils
import volatility.obj as obj
import volatility.win32.tasks as tasks
import volatility.debug as debug
import volatility.commands as commands
import volatility.plugins.filescan as filescan

class ExportException(Exception):
	"""General exception for handling warnings and errors during exporting of files"""
	pass

class ExportFile(filescan.FileScan):
	"""
	Given a PID, _EPROCESS or _FILE_OBJECT, extract the associated (or given) 
	_FILE_OBJECT's from memory.
	
	Pages that can not be retrieved from memory are saved as pages filled in 
	with a given fill byte (--fill).
	
	Exported files are written to a user-defined dump directory (--dir). 
	Contiguous retrievable pages are written to a file named using the 
	retrieved virtual addresses (pages from the shared cache have filenames 
	starting "cache", whilst memory mapped file pages have filenames starting 
	"direct"). In addition, a "this" file is created (a sector "copy" of the 
	file on disk) - this is an aggregation of the retrieved pages with 
	non-retrievable pages substitued by fill-byte pages (--fill) and so, some 
	manual file carving may still be necessary to retrieve the original (disk) 
	file contents. All exported files are placed into a common directory (--dir) 
	whose name and path agree with that located in _FILE_OBJECT (modulo a 
	unix/linux path naming convention).
	
	This plugin is particularly useful when one expects memory to be fragmented, 
	and so, linear carving techniques (e.g. using scalpel or foremost) might be 
	expected to fail. See reference [5] (below) for more information regarding 
	some of the forensic benefits of accessing files via the _FILE_OBJECT data 
	structure.
	
	EXAMPLE 1: Exporting a single FILE_OBJECT
	
	_FILE_OBJECT at 0x81CE4868 is a file named:
	  \\\\Program Files\\\\Mozilla Firefox\\\\chrome\\\\en-US.jar
	with file size 20992 B and has recoverable pages in memory covering file 
	offsets:
	  0x43000 -> 0x45FFF
	  0x47000 -> 0x47FFF
	  0x51000 -> 0x52FFF
	Then:
	  volatility exportfile -f SAMPLE --fobj 0x82106940 --dir EXAMPLE1 --fill 0xff
	would produce:
	  EXAMPLE1/
		Program Files/
		  Mozilla Firefox/
		    chrome/
		      en-US.jar/
		        this
		        cache.0x43000-0x45FFF.dmp
		        cache.0x47000-0x47FFF.dmp
		        cache.0x51000-0x52FFF.dmp
	Where this = fillpages(0xFF) 
	             + cache.0x43000-0x45FFF.dmp 
	             + fillPages(0xFF) 
	             + cache.0x47000-0x47FFF.dmp 
	             + fillPages(0xFF) 
	             + cache.0x51000-0x52FFF.dmp
	and fillPages(0xFF) is a collection of pages filled with the byte 0xFF.
	
	EXAMPLE 2: Exporting multiple _FILE_OBJECT's
	
	Paged pool contains the following two _FILE_OBJECT's:
		1. _FILE_OBJECT at 0x81CE4868 is a file named:
		  \\\\Program Files\\\\Mozilla Firefox\\\\chrome\\\\en-US.jar
		with file size 20992 B and has recoverable pages in memory covering file 
		offsets:
		  0x43000 -> 0x45FFF
		  0x47000 -> 0x47FFF
		  0x51000 -> 0x52FFF
		2. _FILE_OBJECT at 0x81CE4868 is a file named:
		  \\\\Program Files\\\\Mozilla Firefox\\\\chrome\\\\en-US.jar
		with file size 20992 B and has recoverable pages in memory covering file 
		offsets:
		  0x00 -> 0x2FFF
		  0x43000 -> 0x45FFF
	Then:
	  volatility exportfile -f SAMPLE --pool --dir EXAMPLE2
	would produce (amongst other exported _FILE_OBJECT's):
	  EXAMPLE2/
		Program Files/
		  Mozilla Firefox/
		    chrome/
		      en-US.jar/
		        this
		        cache.0x00-0x2FFF.dmp
		        cache.0x43000-0x45FFF.dmp
		        cache.0x47000-0x47FFF.dmp
		        cache.0x51000-0x52FFF.dmp
	Where this = cache.0x00-0x2FFF.dmp
	             +fillpages(0x0) 
	             + cache.0x43000-0x45FFF.dmp 
	             + fillPages(0x0) 
	             + cache.0x47000-0x47FFF.dmp 
	             + fillPages(0x0) 
	             + cache.0x51000-0x52FFF.dmp
	and fillPages(0x0) is a collection of pages filled with the byte 0x0.
	
	TODO: say something about how conflicting pages (i.e. cache.0x43000-0x45FFF.dmp) are overwritten
	
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
		config.add_option("fill", default = 0, type = 'int', action = 'store', help = "Fill character (byte) for padding out missing pages")
		config.add_option("dir", short_option = 'D', type = 'str', action = 'store', help = "Directory in which to save exported files")
		config.add_option("pid", type = 'int', action = 'store', help = "Extract all associated _FILE_OBJECT's from a PID")
		config.add_option("eproc", type = 'int', action = 'store', help = "Extract all associated _FILE_OBJECT's from an _EPROCESS offset (kernel address)")
		config.add_option("fobj", type = 'int', action = 'store', help = "Extract a given _FILE_OBJECT offset (physical address)")
		config.add_option("pool", default = False, action = 'store_true', help = "Extract all _FILE_OBJECT's found by searching the pool")

	def calculate(self):
		self.kernel_address_space = utils.load_as(self._config)
		self.flat_address_space = utils.load_as(self._config, astype = 'physical')
		if not(bool(self._config.DIR)):
			debug.error("--dir needs to be present")
		if not(bool(self._config.pid) ^ bool(self._config.eproc) ^ bool(self._config.fobj) ^ bool(self._config.pool)):
			if not(bool(self._config.pid) or bool(self._config.eproc) or bool(self._config.fobj) or bool(self._config.pool)):
				debug.error("exactly *ONE* of the options --pid, --eproc, --fobj or --pool must be specified (you have not specified _any_ of these options)")
			else:
				debug.error("exactly *ONE* of the options --pid, --eproc, --fobj or --pool must be specified (you have used _multiple_ such options)")
		if bool(self._config.pid):
			# --pid
			eproc_matches = [ eproc for eproc in tasks.pslist(self.kernel_address_space) if eproc.UniqueProcessId == self._config.pid ]
			if len(eproc_matches) != 1:
				debug.error("--pid needs to take a *VALID* PID argument (could not find PID {0} in the process listing for this memory image)".format(self._config.pid))
			return self.dump_from_eproc(eproc_matches[0])
		elif bool(self._config.eproc):
			# --eproc
			return self.dump_from_eproc(obj.Object("_EPROCESS", offset = self._config.eproc, vm = self.kernel_address_space))
		elif bool(self._config.fobj):
			# --fobj
			try:
				return filter(None, [ self.dump_file_object(obj.Object("_FILE_OBJECT", offset = self._config.fobj, vm = self.flat_address_space)) ])
			except ExportException as exn:
				debug.error(exn)
		else:
			# --pool
			return self.dump_from_pool()

	def dump_from_eproc(self, eproc):
		result = []
		if eproc.ObjectTable.HandleTableList:
			for h in eproc.ObjectTable.handles():
				h.kas = self.kernel_address_space
				if h.get_object_type() == "File":
					file_obj = obj.Object("_FILE_OBJECT", h.Body.obj_offset, h.obj_vm)
					try:
						result += [ self.dump_file_object(file_obj) ]
					except ExportException as exn:
						debug.warning(exn)
		return filter(None, result)

	def dump_from_pool(self):
		result = []
		for object_obj, file_obj, name in filescan.FileScan.calculate(self):
			try:
				result += [ self.dump_file_object(file_obj) ]
			except ExportException as exn:
				debug.warning(exn)
		return filter(None, result)

	def render_text(self, outfd, data):
		base_dir = os.path.abspath(self._config.dir)
		for fobj_inst, file_name, file_size, extracted_file_data in data:
			# FIXME: fix this hacky way of creating directory structures
			file_name_path = re.sub(r'[\\:]', '/', base_dir + "/" + file_name)
			if not(os.path.exists(file_name_path)):
				exe.getoutput("mkdir -p {0}".format(re.escape(file_name_path)))
			outfd.write("#"*20)
			outfd.write("\nExporting {0} [_FILE_OBJECT @ 0x{1:08X}]:\n  {2}\n\n".format("Shared Cache" if file_size != None else "Memory Mapped", fobj_inst.v(), file_name))
			if file_size != None:
				# _SHARED_CACHE_MAP processing
				for vacb, section in extracted_file_data:
					with open("{0}/this".format(file_name_path), 'wb') as fobj:
						fobj.write(self.dump_section(outfd, fobj_inst, vacb.BaseAddress, file_size, section, file_name))
			else:
				# _CONTROL_AREA processing
				sorted_extracted_fobjs = sorted(extracted_file_data, key = lambda tup: tup[1])
				for page, start_sector, end_sector in sorted_extracted_fobjs:
					if page != None:
						with open("{0}/direct.0x{1:08X}-0x{2:08X}.dmp".format(file_name_path, start_sector*512, end_sector*512), 'wb') as fobj:
							fobj.write(page)
						outfd.write("Dumped File Offset Range: 0x{0:08X} -> 0x{1:08X}\n".format(start_sector*(4*self.KB), end_sector*(4*self.KB)))
				# TODO: aggregate saved pages into a "this" file
				#last_sector = sorted_extracted_fobjs[-1][2]
				#with open("{0}/this".format(file_name_path), 'wb') as fobj:
				#	fobj.write(self.dump_sectors(outfd, fobj_inst, vacb.BaseAddress, file_size, section, file_name))

	def render_sql(self, outfd, data):
		debug.error("TODO: not implemented yet!")

	KB = 0x400
	_1KB = KB
	MB = _1KB**2
	_1MB = MB
	GB = _1KB**3
	_1GB = GB

	# TODO: monitor issue 151 on Volatility trunk (following code is copied from FileScan)
	def parse_string(self, unicode_obj):
		"""Unicode string parser"""
		# We need to do this because the unicode_obj buffer is in
		# kernel_address_space
		string_length = unicode_obj.Length
		string_offset = unicode_obj.Buffer
        
		string = self.kernel_address_space.read(string_offset, string_length)
		if not string:
			return ''
		return repr(string[:260].decode("utf16", "ignore").encode("utf8", "xmlcharrefreplace"))

	def read_large_integer(self, large_integer):
		return large_integer.HighPart.v() * pow(2, 4 *8) + large_integer.LowPart.v()

	def walk_vacb_tree(self, depth, ptr):
		if depth < 1:
			raise ExportException("consistency check failed (expected VACB tree to have a positive depth)")
		if depth == 1:
			return [ (obj.Object("_VACB", offset = ptr + 4*index, vm = self.kernel_address_space), index) for index in range(0, 128) ]
		return [ (vacb, 128*index + section) for index in range(0, 128) for (vacb, section) in self.walk_vacb_tree(depth-1, ptr+4*index) ]

	def read_vacbs_from_cache_map(self, shared_cache_map, file_size, depth = None, ptr = None):
		if file_size < self._1MB:
			return [ (shared_cache_map.InitialVacbs[index], index) for index in range(0, 4) ]
		else:
			tree_depth = math.ceil((math.ceil(math.log(file_size, 2)) - 18)/7)
			return self.walk_vacb_tree(tree_depth, shared_cache_map.Vacbs.v())

	def dump_file_object(self, file_object):
		if not file_object.is_valid():
			raise ExportException("consistency check failed (expected [_FILE_OBJECT @ 0x{0:08X}] to be a valid physical address)".format(file_object.v()))
		file_name = self.parse_string(file_object.FileName)
		if file_name == None:
			raise ExportException("consistency check failed [_FILE_OBJECT @ 0x{0:08X}] (expected file name to be non-null)".format(file_object.v()))
		if len(file_name) > 0 and file_name[0] == "\'":
			file_name = file_name[1:]
		if len(file_name) > 0 and file_name[-1] == "\'":
			file_name = file_name[0:-1]
		DSO = 0 # DataSectionObject
		SCM = 1 # SharedCacheMap
		ISO = 2 # ImageSectionObject
		classify = [ False, False, False ] # [ DSO != None, SCM != None, ISO != None ]
		section_object_ptr = obj.Object('_SECTION_OBJECT_POINTERS', offset = file_object.SectionObjectPointer, vm = self.kernel_address_space)
		if section_object_ptr.DataSectionObject != 0 and section_object_ptr.DataSectionObject != None:
			classify[DSO] = True
		if section_object_ptr.SharedCacheMap != 0 and section_object_ptr.SharedCacheMap != None:
			classify[SCM] = True
		if section_object_ptr.ImageSectionObject != 0 and section_object_ptr.ImageSectionObject != None:
			classify[ISO] = True

		if not(classify[DSO]) and not(classify[SCM]) and not(classify[ISO]):
			raise ExportException("all members of _SECTION_OBJECT_POINTERS [_FILE_OBJECT @ 0x{0:08X}] are null, and they shouldn't be!".format(file_object.v()))
		if not(classify[DSO]) and not(classify[ISO]):
			raise ExportException("{0}\n  has no _CONTROL_AREA object (as no DataSectionObject and no ImageSectionObject exists for the _SECTION_OBJECT_POINTERS [_FILE_OBJECT @ 0x{1:08X}]), and one should exist!".format(file_name, file_object.v()))
		if classify[SCM]:
			# Shared Cache Map
			shared_cache_map = obj.Object('_SHARED_CACHE_MAP', offset = section_object_ptr.SharedCacheMap, vm = self.kernel_address_space)
			file_size = self.read_large_integer(shared_cache_map.FileSize)
			if self.read_large_integer(shared_cache_map.ValidDataLength) > file_size:
				raise ExportException("consistency check failed [_FILE_OBJECT @ 0x{0:08X}] (expected ValidDataLength to be bounded by file size)".format(file_object.v()))
			return (file_object, file_name, file_size, [ (vacb, section) for (vacb, section) in self.read_vacbs_from_cache_map(shared_cache_map, file_size) if vacb != 0 and vacb != None ])
		elif classify[DSO]:
			# Data Section Object
			return (file_object, file_name, None, self.dump_control_area(obj.Object("_CONTROL_AREA", offset = section_object_ptr.DataSectionObject, vm = self.kernel_address_space)))
		else:
			# Image Section Object
			return (file_object, file_name, None, self.dump_control_area(obj.Object("_CONTROL_AREA", offset = section_object_ptr.ImageSectionObject, vm = self.kernel_address_space)))

	def walk_subsections(self, ptr):
		if ptr == 0 or ptr == None:
			return []
		return [ ptr ] + self.walk_subsections(ptr.NextSubsection)

	# TODO: take into account the PTE flags when reading pages?
	def read_pte_array(self, base_addr, num_of_ptes):
		result = []
		for pte in range(0, num_of_ptes):
			if self.kernel_address_space.is_valid_address(base_addr + 4*pte):
				(pte_addr, ) = struct.unpack('=I', self.kernel_address_space.read(base_addr + 4*pte, 4))
				page_phy_addr = pte_addr & 0xFFFFF000
				if page_phy_addr != 0 and self.flat_address_space.is_valid_address(page_phy_addr):
					result += [ (self.flat_address_space.read(page_phy_addr, 4*self.KB), pte) ]
				else:
					result += [ (None, pte) ]
			else:
				result += [ (None, pte) ]
		return result

	def dump_control_area(self, control_area):
		result = []
		start_subsection = obj.Object("_SUBSECTION", offset = control_area.v() + control_area.size(), vm = self.kernel_address_space)
		subsection_list = self.walk_subsections(start_subsection)
		for subsection, index in zip(subsection_list, range(0, len(subsection_list))):
			start_sector = subsection.StartingSector
			num_of_sectors = subsection.NumberOfFullSectors
			result += [ (page, start_sector + pte_index*8, start_sector + (pte_index + 1)*8) for page, pte_index in self.read_pte_array(subsection.SubsectionBase.v(), subsection.PtesInSubsection) if pte_index <= num_of_sectors and page != None ]
		return result

	def dump_pages(self, outfd, data, addr, start, end, section, base_dir):
		with open("{0}/cache.0x{1:08X}-0x{2:08X}.dmp".format(base_dir, section*(256*self.KB) + start*(4*self.KB), section*(256*self.KB) + end*(4*self.KB) - 1), 'wb') as fobj:
			fobj.write(data)
		header_str = "Dumped File Offset Range: 0x{0:08X} -> 0x{1:08X}".format(section*(256*self.KB) + start*(4*self.KB), section*(256*self.KB) + end*(4*self.KB) - 1)
		outfd.write(header_str)
		outfd.write("\n")

	def dump_section(self, outfd, file_object, addr, size, section, file_name):
		max_page = (size/(4*self.KB)) + 1
		section_data = ""
		result = ""
		padding = ""
		fill_char = chr(self._config.fill % 256)
		base_dir = re.sub(r'[\\:]', '/', self._config.dir + "/" + file_name)
		last_page = 0
		for page in range(0, max_page):
			if self.kernel_address_space.is_valid_address(addr + page*(4*self.KB)):
				if padding != "":
					section_data += padding
				padding = ""
				if page > 0 and result == "":
					last_page = page
				result += self.kernel_address_space.read(addr + page*(4*self.KB), (4*self.KB))
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
    