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
import os
import os.path
import math
import struct
import hashlib
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
	
	Exported files are written to a user-defined dump directory (--dir). 
	Contiguous retrievable pages are written to a file named using the 
	retrieved virtual addresses:
	
	  pages from _SHARED_CACHE_MAP are saved in files named cache.0xXX-0xXX.dmp.MD5
	
	  pages from _CONTROL_AREA are saved in files named direct.0xXX-0xXX.dmp.MD5
	
	where MD5 stands for the hash of the files contents.
	
	Pages that can not be retrieved from memory are saved as pages filled in 
	with a given fill byte (--fill).
	
	In addition, a "this" file is created (a sector "copy" of the file on disk) 
	- this is an aggregated reconstruction based on the retrievable pages above 
	and, with non-retrievable pages substitued by fill-byte pages (--fill). Some 
	slack space editing may still be necessary to retrieve the original (user 
	view) file contents. All exported files are placed into a common directory 
	(base of which is determined by --dir) whose name and path agree with that 
	located in _FILE_OBJECT (modulo a unix/linux path naming convention).
	
	This plugin is particularly useful when one expects memory to be fragmented, 
	and so, linear carving techniques (e.g. using scalpel or foremost) might be 
	expected to fail. See reference [5] (below) for more information regarding 
	some of the forensic benefits of accessing files via the _FILE_OBJECT data 
	structure.
	
	EXAMPLE:
	
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
		        cache.0x43000-0x45FFF.dmp.MD5
		        cache.0x47000-0x47FFF.dmp.MD5
		        cache.0x51000-0x52FFF.dmp.MD5
	Where this = fillpages(0xFF)
	             + cache.0x43000-0x45FFF.dmp.MD5
	             + fillPages(0xFF)
	             + cache.0x47000-0x47FFF.dmp.MD5
	             + fillPages(0xFF)
	             + cache.0x51000-0x52FFF.dmp.MD5
	and fillPages(0xFF) is a collection of pages filled with the byte 0xFF.
	
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
	[7] OSR Online article: Cache Me If You Can: Using the NT Chace Manager (accessed 14/Oct/2011):
	    http://www.osronline.com/article.cfm?id=167
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
		config.add_option("reconstruct", default = False, action = 'store_true', help = "Do not export file objects, perform file reconstruction on previously extracted file pages")

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
				file_object = obj.Object("_FILE_OBJECT", offset = self._config.fobj, vm = self.flat_address_space)
				if bool(self._config.reconstruct):
					# --reconstruct
					return [ (file_object, self.parse_string(file_object.FileName)) ]
				else:
					return filter(None, [ self.dump_file_object(file_object) ])
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
						if bool(self._config.reconstruct):
							# --reconstruct
							result += [ (file_obj, self.parse_string(file_obj.FileName)) ]
						else:
							result += [ self.dump_file_object(file_obj) ]
					except ExportException as exn:
						debug.warning(exn)
		return filter(None, result)

	def dump_from_pool(self):
		result = []
		for object_obj, file_obj, name in filescan.FileScan.calculate(self):
			try:
				if bool(self._config.reconstruct):
					# --reconstruct
					result += [ (file_obj, name) ]
				else:
					result += [ self.dump_file_object(file_obj) ]
			except ExportException as exn:
				debug.warning(exn)
		return filter(None, result)

	def render_text(self, outfd, data):
		base_dir = os.path.abspath(self._config.dir)
		if bool(self._config.reconstruct):
			# Perform no file extraction, simply reconstruct existing extracted file pages
			for file_object, file_name in data:
				file_name_path = re.sub(r'\'', '', re.sub(r'//', '/', re.sub(r'[\\:]', '/', base_dir + "/" + file_name)))
				self.reconstruct_file(outfd, file_object, file_name_path)
		else:
			# Process extracted file page data and then perform file reconstruction upon the results
			for file_data in data:
				for data_type, fobj_inst, file_name, file_size, extracted_file_data in file_data:
					# FIXME: fix this hacky way of creating directory structures
					file_name_path = re.sub(r'\'', '', re.sub(r'//', '/', re.sub(r'[\\:]', '/', base_dir + "/" + file_name)))
					if not(os.path.exists(file_name_path)):
						exe.getoutput("mkdir -p {0}".format(re.escape(file_name_path)))
					outfd.write("#"*20)
					outfd.write("\nExporting {0} [_FILE_OBJECT @ 0x{1:08X}]:\n  {2}\n\n".format(data_type, fobj_inst.v(), file_name))
					if data_type == "_SHARED_CACHE_MAP":
						# _SHARED_CACHE_MAP processing
						self.dump_shared_pages(outfd, data, fobj_inst, file_name_path, file_size, extracted_file_data)
					elif data_type == "_CONTROL_AREA":
						# _CONTROL_AREA processing
						self.dump_control_pages(outfd, data, fobj_inst, file_name_path, extracted_file_data)
					self.reconstruct_file(outfd, fobj_inst, file_name_path)

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
		section_object_ptr = obj.Object('_SECTION_OBJECT_POINTERS', offset = file_object.SectionObjectPointer, vm = self.kernel_address_space)
		result = []
		if section_object_ptr.DataSectionObject != 0 and section_object_ptr.DataSectionObject != None:
			# Shared Cache Map
			try:
				shared_cache_map = obj.Object('_SHARED_CACHE_MAP', offset = section_object_ptr.SharedCacheMap, vm = self.kernel_address_space)
				if shared_cache_map == None:
					raise ExportException("consistency check failed [_FILE_OBJECT @ 0x{0:08X}] (expected _SHARED_CACHE_MAP to be non-null)".format(file_object.v()))
				if shared_cache_map.FileSize == None:
					raise ExportException("consistency check failed [_FILE_OBJECT @ 0x{0:08X}] (expected FileSize to be non-null)".format(file_object.v()))
				file_size = self.read_large_integer(shared_cache_map.FileSize)
				if self.read_large_integer(shared_cache_map.ValidDataLength) > file_size:
					raise ExportException("consistency check failed [_FILE_OBJECT @ 0x{0:08X}] (expected ValidDataLength to be bounded by file size)".format(file_object.v()))
				result += [ ("_SHARED_CACHE_MAP", file_object, file_name, file_size, self.dump_shared_cache_map(shared_cache_map, file_size)) ]
			except ExportException as exn:
				debug.warning(exn)
		if section_object_ptr.DataSectionObject != 0 and section_object_ptr.DataSectionObject != None:
			# Data Section Object
			try:
				control_area = obj.Object("_CONTROL_AREA", offset = section_object_ptr.DataSectionObject, vm = self.kernel_address_space)
				result += [ ("_CONTROL_AREA", file_object, file_name, None, self.dump_control_area(control_area)) ]
			except ExportException as exn:
				debug.warning(exn)
		if section_object_ptr.ImageSectionObject != 0 and section_object_ptr.ImageSectionObject != None:
			# Image Section Object
			try:
				control_area = obj.Object("_CONTROL_AREA", offset = section_object_ptr.ImageSectionObject, vm = self.kernel_address_space)
				result += [ ("_CONTROL_AREA", file_object, file_name, None, self.dump_control_area(control_area)) ]
			except ExportException as exn:
				debug.warning(exn)
		return result

	def walk_subsections(self, ptr):
		if ptr == 0 or ptr == None:
			return []
		return [ ptr ] + self.walk_subsections(ptr.NextSubsection)

	# TODO: take into account the PTE flags when reading pages (output via debug.warning?)
	def read_pte_array(self, subsection, base_addr, num_of_ptes):
		result = []
		for pte in range(0, num_of_ptes):
			if not(self.kernel_address_space.is_valid_address(base_addr + 4*pte)):
				raise ExportException("consistency check failed (expected PTE to be at a valid address)")
			(pte_addr, ) = struct.unpack('=I', self.kernel_address_space.read(base_addr + 4*pte, 4))
			page_phy_addr = pte_addr & 0xFFFFF000
			if page_phy_addr != 0 and self.flat_address_space.is_valid_address(page_phy_addr) and page_phy_addr != subsection.v():
				result += [ (self.flat_address_space.read(page_phy_addr, 4*self.KB), pte) ]
			elif page_phy_addr != 0:
				result += [ (None, pte) ]
		return result

	def dump_shared_cache_map(self, shared_cache_map, file_size):
		# _VACB points to a 256KB area of paged memory. Parts of this memory may be paged out, so we perform a linear search, 
		# through our set of _VACB page addresses, looking for valid in-memory pages.
		result = []
		for vacb, section in self.read_vacbs_from_cache_map(shared_cache_map, file_size):
			if vacb != 0 and vacb != None:
				vacb_base_addr = vacb.BaseAddress.v()
				for page in range(0, 64):
					if self.kernel_address_space.is_valid_address(vacb_base_addr + page*(4*self.KB)):
						result += [ (self.kernel_address_space.read(vacb_base_addr + page*(4*self.KB), (4*self.KB)), section*(256*self.KB) + page*(4*self.KB), section*(256*self.KB) + (page + 1)*(4*self.KB) - 1) ]
		return result

	def dump_control_area(self, control_area):
		result = []
		start_subsection = obj.Object("_SUBSECTION", offset = control_area.v() + control_area.size(), vm = self.kernel_address_space)
		subsection_list = self.walk_subsections(start_subsection)
		sector = None
		for subsection, index in zip(subsection_list, range(0, len(subsection_list))):
			start_sector = subsection.StartingSector
			num_of_sectors = subsection.NumberOfFullSectors
			if sector == None:
				sector = start_sector
			sector_data = [ (page, pte_index) for page, pte_index in self.read_pte_array(subsection, subsection.SubsectionBase.v(), subsection.PtesInSubsection) if pte_index <= num_of_sectors and page != None ]
			result += map(lambda ((page, pte_index), position): (page, sector + position*8), zip(sector_data, range(0, len(sector_data))))
			sector += len(sector_data)*8
		return result

	def dump_data(self, outfd, data, dump_file, start_addr, end_addr):
		if not os.path.exists(dump_file):
			with open(dump_file, 'wb') as fobj:
				fobj.write(data)
			outfd.write("Dumped File Offset Range: 0x{0:08X} -> 0x{1:08X}\n".format(start_addr, end_addr))
		else:
			outfd.write("..Skipping File Offset Range: 0x{0:08X} -> 0x{1:08X}\n".format(start_addr, end_addr))

	def dump_shared_pages(self, outfd, data, file_object, file_name_path, file_size, extracted_file_data):
		for vacb, start_addr, end_addr in extracted_file_data:
			vacb_hash = hashlib.md5(vacb).hexdigest()
			vacb_path = "{0}/cache.0x{1:08X}-0x{2:08X}.dmp.{3}".format(file_name_path, start_addr, end_addr, vacb_hash)
			self.dump_data(outfd, vacb, vacb_path, start_addr, end_addr)

	def dump_control_pages(self, outfd, data, file_object, file_name_path, extracted_file_data):
		sorted_extracted_fobjs = sorted(extracted_file_data, key = lambda tup: tup[1])
		for page, start_sector in sorted_extracted_fobjs:
			if page != None:
				start_addr = start_sector*512
				end_addr = (start_sector + 8)*512 - 1
				page_hash = hashlib.md5(page).hexdigest()
				page_path = "{0}/direct.0x{1:08X}-0x{2:08X}.dmp.{3}".format(file_name_path, start_addr, end_addr, page_hash)
				self.dump_data(outfd, page, page_path, start_addr, end_addr)

	def reconstruct_file(self, outfd, file_object, file_name_path):
		def check_for_overlaps(data):
			# ASSUME: data is sorted by (start_addr, end_addr, md5)
			while len(data) >= 2:
				end_addr1 = data[0][2]
				start_addr2 = data[1][1]
				if start_addr2 <= end_addr1:
					if os.path.exists("{0}/this".format(file_name_path)):
						# We're about to fail with reconstruction, eliminate any old "this" files from previous reconstruction attempts
						os.remove("{0}/this".format(file_name_path))
					raise ExportException("File Reconstruction Failed: overlapping page conflict (for address range 0x{0:08X}-0x{1:08X}) detected during file reconstruction - please manually fix and use --reconstruct to attempt rebuilding the file".format(start_addr2, end_addr1))
				data = data[1:]
		
		outfd.write("[_FILE_OBJECT @ 0x{0:08X}] Reconstructing extracted memory pages from:\n  {1}\n".format(file_object.v(), file_name_path))
		fill_char = chr(self._config.fill % 256)
		if os.path.exists(file_name_path):
			# list files in file_name_path
			raw_page_dumps = [ f for f in os.listdir(file_name_path) if re.search("(cache|direct)\.0x[a-fA-F0-9]{8}\-0x[a-fA-F0-9]{8}\.dmp(\.[a-fA-F0-9]{32})?$", f) ]
			# map file list to (dump_type, start_addr, end_addr, data, md5) tuple list
			page_dumps = []
			for dump in raw_page_dumps:
				dump_type, addr_range, ignore, md5 = dump.split(".")
				start_addr, end_addr = map(lambda x: x[2:], addr_range.split("-"))
				data = ""
				with open("{0}/{1}".format(file_name_path, dump), 'r') as fobj:
					data = fobj.read()
				if hashlib.md5(data).hexdigest() != md5:
					debug.error("consistency check failed (MD5 checksum check for {0} failed!)".format(dump))
				page_dumps += [ (dump_type, int(start_addr, 16), int(end_addr, 16), data, md5) ]
			try:
				# check for page overlaps
				extracted_file_data = sorted(page_dumps, key = lambda x: (x[1], x[2], x[3]))
				check_for_overlaps(extracted_file_data)
				# glue remaining file pages together and save reconstructed file as "this"
				with open("{0}/this".format(file_name_path), 'wb') as fobj:
					offset = 0
					for data_type, start_addr, end_addr, data, data_hash in extracted_file_data:
						if offset > end_addr:
							break
						if offset < start_addr:
							fobj.write(fill_char*(start_addr - offset))
						fobj.write(data)
						offset = end_addr + 1
				outfd.write("Successfully Reconstructed File\n")
			except ExportException as exn:
				debug.warning(exn)
		else:
			outfd.write("..Skipping file reconstruction due to a lack of extracted pages\n")
