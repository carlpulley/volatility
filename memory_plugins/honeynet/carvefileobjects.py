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
    
fobjs = [ 0x01e6f2d8, 0x01e764c8, 0x01e8aad8, 0x01e8c8e8, 0x01f16360, 0x01f19eb8, 0x01f22df8, 0x01ffaaf0, 0x01ffadf0, 0x020c1960, 0x020c8f90, 0x0226f028, 0x0227de50, 0x022c50d0, 0x022c7b98, 0x022cbf90, 0x022cebd8, 0x022da3d8, 0x022da470, 0x022e2520, 0x022f11b0, 0x024137f8, 0x02413890, 0x025b3dd8 ]
for fobj in fobjs:
    try:
        dump_file_object(fobj, base_dir)
    except:
        print "ERROR: failed to dump _FILE_OBJECT %02x!"%fobj
    