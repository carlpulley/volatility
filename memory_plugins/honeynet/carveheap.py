"""
@author:       Carl Pulley
@license:      GNU General Public License 2.0 or later
@contact:      c.j.pulley@hud.ac.uk
@organization: University of Huddersfield
"""

import re
import commands
import os.path
import sqlite3
import fileobjscan

KB = 0x400
_1KB = KB
MB = _1KB**2
_1MB = MB
GB = _1KB**3
_1GB = GB
_true = 1
_false = 0

self.types.update(fileobjscan.extra_types)
self.flat_address_space = find_addr_space(FileAddressSpace(self.opts.filename), self.types)

class HeapCorruption(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)

def get_virtual_allocations(heap):
    # TODO: check that this code is correct!
    # TODO: how large are these allocations?
    if not heap.is_valid() or heap.VirtualAllocdBlocks == None:
        return []
    return [ block for block in list_entry(heap.VirtualAllocdBlocks, '_HEAP_ENTRY', obj_size(self.types, '_HEAP_ENTRY')) if block.is_valid() ]

def get_free_list(_list_entry):
    return [ Object('_HEAP_ENTRY', heap_entry.value(), self.process_address_space, profile=self.eproc.profile) for heap_entry in list_entry(_list_entry, '_HEAP_ENTRY', obj_size(self.types, '_HEAP_ENTRY')) ]

def get_free_lists(heap):
    free_lists = []
    for offset in range(0, 128):
        if offset == 1:
            continue
        _list_entry = heap.FreeLists[offset]
        if _list_entry == None or _list_entry == 0x0:
            free_lists += [(offset, [])]
        else:
            free_lists += [ (offset, get_free_list(_list_entry)) ]
    return [ (offset,free_data) for (offset,free_data) in free_lists if free_data != [] ]

def get_segments(heap):
    return [ Object('_HEAP_SEGMENT', offset, self.process_address_space, profile=self.eproc.profile) for offset in heap.Segments if offset != None and offset != 0x0 ]

def get_heap_entry_iter(segment_end, heap_entry):
    while heap_entry != None and not isinstance(heap_entry, HeapCorruption):
        old_heap_entry = heap_entry
        if heap_entry.v() == segment_end:
            return
        elif heap_entry.v() > segment_end:
            heap_entry = HeapCorruption("Attempted to seek beyond the end of the heap segment 0x%0.8X"%segment_end)
        elif not heap_entry.is_valid(): 
            heap_entry = None
        elif heap_entry.Size == 0: 
            return
        else:
            heap_entry = Object('_HEAP_ENTRY', heap_entry.v() + heap_entry.Size, self.process_address_space, profile=self.eproc.profile)
        yield old_heap_entry
        
def get_heap_entries(heap):
    result = []
    for segment in get_segments(heap):
        entries = [ entry for entry in get_heap_entry_iter(segment.LastValidEntry.offset, segment.FirstEntry) ]
        if segment.FirstEntry.offset != segment.LastEntryInSegment.offset:
            entries += [ entry for entry in get_heap_entry_iter(segment.LastValidEntry.offset, segment.LastEntryInSegment) ]
        result += [entries]
    return result

def carve_heap(heap):
    if not heap.is_valid():
        print "** Heap @ 0x%0.8X currently paged out"%(heap.value())
        return
    segments = get_segments(heap)
    print "** Heap @ 0x%0.8X: %s"%(heap.offset, str([ "0x%0.8x"%seg.offset for seg in segments ]))
    #[ db(seg.value(), seg.size()) for seg in segments if seg.is_valid() ]
    free_lists = get_free_lists(heap)
    print "** Heap Free Lists: %s"%(str([ (index, ["0x%0.8x"%fl.offset for fl in free_data]) for (index, free_data) in free_lists ]))
    #[ db(fl.offset, min(index*8+fl.size() if index != 0 else fl.Size, 0x80)) for (index, item) in free_lists for fl in item ]
    virtual_allocations = get_virtual_allocations(heap)
    print "** Virtual Allocations: %s"%(str([ alloc.offset for alloc in virtual_allocations ]))
    [ db(alloc.offset) for alloc in virtual_allocations ]
    heap_allocations = get_heap_entries(heap)
    print "** Heap Allocations:\n"
    for allocations in heap_allocations:
        for heap_entry in allocations:
            if isinstance(heap_entry, HeapCorruption):
                print heap_entry
            elif heap_entry == None:
                print "Paged data hit"
            else:
                db(heap_entry.offset, min(heap_entry.Size if heap_entry.is_valid() else 0x80, 0x80))
    print "*"*30
   
def get_heaps(peb):
    return [ Object('_HEAP', read_value(self.process_address_space, 'pointer', peb.ProcessHeaps.offset + offset*4), self.process_address_space, profile=self.eproc.profile) for offset in range(0, peb.MaximumNumberOfHeaps) ]
    
def carve_heaps(eproc=None):
    if eproc == None:
        eproc = self.image_offset
    old_eproc = self.image_offset
    if self.image_offset != eproc:
        cc(offset=eproc)
    print "Carve Heaps for process %d"%self.image_pid
    peb = self.eproc.Peb
    if peb.is_valid():
        print "Default process heap is at 0x%0.8X"%peb.ProcessHeap.v()
        [ carve_heap(heap) for heap in get_heaps(peb) ]
    else:
        print "WARNING: failed to carve process heaps"
    if old_eproc != eproc:
        cc(offset=old_eproc)

