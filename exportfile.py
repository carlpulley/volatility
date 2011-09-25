"""
@author:       Carl Pulley
@license:      GNU General Public License 2.0 or later
@contact:      c.j.pulley@hud.ac.uk
@organization: University of Huddersfield
"""

import re
import commands
import os.path
import fileobjscan

KB = 0x400
_1KB = KB
MB = _1KB**2
_1MB = MB
GB = _1KB**3
_1GB = GB

self.types.update(fileobjscan.extra_types)
self.flat_address_space = find_addr_space(FileAddressSpace(self.opts.filename), self.types)

def my_read_time(addr_space, types, member_list, vaddr):
    (offset, _) = get_obj_offset(types, member_list)
		
    low_time  = read_obj(addr_space, types, ['_KSYSTEM_TIME', 'LowPart'], vaddr+offset)
    high_time = read_obj(addr_space, types, ['_KSYSTEM_TIME', 'High1Time'], vaddr+offset)
    
    if low_time == None or high_time == None:
        return None
    
    return (high_time << 32) | low_time

def read_long_integer(addr_space, types, members_list, vaddr):
    return my_read_time(addr_space, types, members_list, vaddr)

def vacb_node_size(file_size):
    if not isinstance(file_size, int):
        raise Exception("ERROR: file_size should be an integer!")
    if file_size < _1MB:
        return 1
    elif file_size < 32*MB:
        return 4
    else:
        return 128

def size_str(size):
    size_str = size
    units = ""
    if size % _1MB == size:
        size_str = size/_1KB
        units = "K"
    elif size % _1GB == size:
        size_str = size/_1MB
        units = "M"
    else:
        size_str = size/_1GB
        units = "G"
    return "%d%c"%(size_str, units)

def read_vacbs_from_cache_map(vaddr, node_size=1):
    if node_size == 1:
        return [ (read_value(self.process_address_space, 'pointer', read_obj(self.process_address_space, self.types, ['_SHARED_CACHE_MAP', 'Vacbs'], vaddr)), 0) ]
    elif node_size == 4:
        return [ (read_value(self.process_address_space, 'pointer', read_obj(self.process_address_space, self.types, ['_SHARED_CACHE_MAP', 'Vacbs'], vaddr) + node_size*index), index) for index in range(0, node_size) ]
    elif node_size == 128:
        # TODO: calculate vacb tree depth
        # TODO: traverse vacb tree and grab vacb addresses
        raise Exception("TODO: not implemented yet!")
    else:
        raise Exception("ERROR: %d is an invalid node size - nodes may only be 1, 4 or 128 element array(s)"%node_size)

def render_data(data, addr, start, end, section, base_dir):
    # TODO: write data out to an SQLite3 database table instead
    with open("%s/cache.0x%02X-0x%02X.dmp"%(base_dir, section*(256*KB) + start*(4*KB), section*(256*KB) + end*(4*KB) - 1), 'wb') as fobj:
        fobj.write(data)
    header_str = "File Offset Range: 0x%02X -> 0x%02X"%(section*(256*KB) + start*(4*KB), section*(256*KB) + end*(4*KB) - 1)
    print header_str
    print "*"*len(header_str)
    db(addr)

def dump_section(addr, size, section, base_dir):
    # TODO: when using SQLite3 database tables to model a file and tables to model its pages, there's no need to define section_data here
    #         - a separate database related function is used to extract/export data for further analysis
    max_page = (size/(4*KB)) + 1
    section_data = ""
    result = ""
    padding = ""
    last_page = 0
    for page in range(0, max_page):
        if self.process_address_space.is_valid_address(addr + page*(4*KB)):
            if padding != "":
                section_data += padding
            padding = ""
            if page > 0 and result == "":
                last_page = page
            result += self.process_address_space.read(addr + page*(4*KB), (4*KB))
        else:
            padding += '\0'*(4*KB)
            if result != "":
                section_data += result
                render_data(result, addr + last_page*(4*KB), last_page, page, section, base_dir)
            result = ""
    if padding != "":
        section_data += padding
    if result != "":
        section_data += result
        render_data(result, addr + last_page*(4*KB), last_page, max_page, section, base_dir)
    return section_data

def dump_file_object(fobj_phy_addr, base_dir="."):
    # TODO: when writing section pages, need to detect overwrites and compare for sanities sake!?
    # ASSUME: that self.eproc defines the correct context for the _EPROCESS object owning our _FILE_OBJECT (ie. fobj_phy_addr)
    base_dir = os.path.abspath(base_dir)
    section_obj_ptr = read_obj(self.flat_address_space, self.types, ['_FILE_OBJECT', 'SectionObjectPointer'], fobj_phy_addr)
    file_name = read_unicode_string_p(self.flat_address_space, self.process_address_space, self.types, ['_FILE_OBJECT', 'FileName'], fobj_phy_addr)
    if file_name == None:
        raise Exception("ERROR: expected file name to be non-null!")
    shared_cache_map = read_obj(self.process_address_space, self.types, ['_SECTION_OBJECT_POINTERS', 'SharedCacheMap'], section_obj_ptr)
    if shared_cache_map != 0 and shared_cache_map != None:
        file_size = read_long_integer(self.process_address_space, self.types, ['_SHARED_CACHE_MAP', 'FileSize'], shared_cache_map)
        if file_size == None:
            raise Exception("ERROR: expected file size to be non-null!")
        vacb_list = read_vacbs_from_cache_map(shared_cache_map, vacb_node_size(file_size))
        print "Dumping Shared Cache Map for:\n  %s (%s bytes)\n"%(file_name, size_str(file_size))
        # FIXME: fix this hacky way of creating directory structures
        file_name_path = re.sub(r'[\\:]', '/', base_dir + "/" + file_name)
        if not os.path.exists(file_name_path):
            commands.getoutput("mkdir -p %s"%re.escape(file_name_path))
        # TODO: create an SQLite3 database for storing related file object data
        with open("%s/this"%file_name_path, 'wb') as fobj:
            [ fobj.write(data) for data in [ dump_section(read_obj(self.process_address_space, self.types, ['_VACB', 'BaseAddress'], vacb), file_size, section, file_name_path) for (vacb, section) in vacb_list if vacb != 0 and vacb != None ] ]
    else:
        print "WARNING: No Shared Cache Map for:\n  %s"%file_name

class ExportFile(filescan.FileScan):
	"""Given a _FILE_OBJECT, extract (saving to disk) the associated file from memory (with paged-out sections being padded with a given fill character - 0x0 by default)
	"""
	# Declare meta information associated with this plugin
    meta_info = {}
    meta_info['author'] = 'Carl Pulley'
    meta_info['contact'] = 'c.j.pulley@hud.ac.uk'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://compeng.hud.ac.uk/scomcjp/'
    meta_info['os'] = ['WinXPSP3x86', 'WIN_32_XP_SP2']
    meta_info['version'] = '0.1'
   
	def __init__(self, config, args*):
		config.add_option("fill", default = 0x0, type = 'int', help = "fill character for padding paged-out files")
		config.add_option("dir", short_option = 'd', default = ".", type = 'str', help = "directory in which to save exported files")
		# FIXME: only one of the following options must be present, but not all of them!
		config.add_option("pid", type = 'int', help = "extract all _FILE_OBJECT's for a PID")
		config.add_option("eproc", type = 'str', help = "extract all _FILE_OBJECT's for an _EPROCESS")
		config.add_option("fobj", type = 'str', help = "extract a given _FILE_OBJECT")
		commands.command.__init__(self, config, args*)
		self.kernel_address_space = None
		
	def calculate(self):
		if self._config.fobj:
			dump_file_object(self._config.fobj, self._config.dir)
		elif self._config.pid:
			# FIXME: need to extract all _FILE_OBJECT's under given _EPROCESS (obtained from PID)
			for fobj in self._config.pid:
				dump_file_object(fobj, self._config.dir)
		elif self._config.eproc:
			# FIXME: need to extract all _FILE_OBJECT's under given _EPROCESS
			for fobj in self._config.eproc:
				dump_file_object(fobj, self._config.dir)
		else:
			# FIXME: generate an error message - we shouldn't get here!
		
	def render_text(self, outfd, data):
		pass
    