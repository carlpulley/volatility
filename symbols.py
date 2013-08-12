#!/usr/bin/env python
#
# symbols.py
# Copyright (C) 2013 Carl Pulley <c.j.pulley@hud.ac.uk>
#
# Donated under Volatility Foundation, Inc. Individual Contributor Licensing
# Agreement
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
Code here is designed to resolve addresses to the nearest function/method name 
within a symbol table. 

When the --symbols option is specified, symbol tables are built using Microsoft's 
debugging symbol information. The symbol PDB files are downloaded and cached within 
Volatility's caching directories.

If --symbols is not specified or no symbol information is available, then module 
exports information is used to populate the symbols tables.

@author:       Carl Pulley
@license:      GNU General Public License 2.0 or later
@contact:      c.j.pulley@hud.ac.uk

DEPENDENCIES:
  blist
  construct (pdbparse dependency)
  pdbparse (along with cabextract or 7z) - need to install >= 1.1 [>= r104]
  pefile (pdbparse dependency)

REFERENCES:
[1] Fog, A. (2012). Calling conventions for different C++ compilers and operating systems. 
    Retrieved from:
      http://www.agner.org/optimize/calling_conventions.pdf
[2] Using the Mozilla symbol server. Retrieved 3/Apr/2013 from:
      https://developer.mozilla.org/en/docs/Using_the_Mozilla_symbol_server
[3] Dolan-Gavitt, B. (2007). pdbparse - Open-source parser for Microsoft debug symbols. 
    Retrieved 31/Mar/2013 from:
      https://code.google.com/p/pdbparse/
[4] Starodumov, O. (2004). Matching debug information. Retrieved from:
      http://www.debuginfo.com/articles/debuginfomatch.html
[5] Mozilla (2007) symbolstore - Runs dump_syms over debug info files. Retrieved 
    7/Apr/2013 from:
      http://mxr.mozilla.org/mozilla-central/source/toolkit/crashreporter/tools/symbolstore.py
"""

try:
  import pdbparse
  import pdbparse.peinfo
  from pdbparse.undecorate import undecorate as msvc_undecorate
  from pdbparse.undname import undname as msvcpp_undecorate
  pdbparse_installed = True
except ImportError:
  pdbparse_installed = False
from inspect import isfunction
import ntpath
import os
from operator import attrgetter
import sys
import time
from urllib import FancyURLopener
import urllib2
import volatility.commands as commands
import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.overlays.windows.windows as windows
import volatility.utils as utils
import volatility.win32.tasks as tasks
try:
  from blist import sorteddict
except ImportError:
  debug.error("this code uses a sorteddict for building the symbol table - please install blist")

# URLs to query when searching for debugging symbols
SYM_URLS = [ 'http://msdl.microsoft.com/download/symbols', 'http://symbols.mozilla.org/firefox', 'http://chromium-browser-symsrv.commondatastorage.googleapis.com' ]
# number of hours to wait before attempting a failed debugging symbols download (default is 1 year)
RETRY_TIMEOUT = 365*24 

class NameParser(object):
  def undecorate(self, dname):
    if dname.startswith("?"):
      # TODO: calculate stack space
      calling_conv = "UNDEFINED"
      parsed_calling_conv = filter(lambda x: x in ["__cdecl", "__pascal", "__thiscall", "__stdcall", "__fastcall", "__clrcall"], msvcpp_undecorate(dname, flags=0x0).split(" "))
      if len(parsed_calling_conv) == 1:
        calling_conv = parsed_calling_conv[0]
      return (msvcpp_undecorate(dname), -1, calling_conv)
    else:
      return msvc_undecorate(dname)

# Following is based on code taken from [3]:
#   https://code.google.com/p/pdbparse/source/browse/trunk/pdbparse/symchk.py
class PDBOpener(FancyURLopener):
  version = "Microsoft-Symbol-Server/6.6.0007.5"
  def http_error_default(self, url, fp, errcode, errmsg, headers):
    if errcode == 404:
      raise urllib2.HTTPError(url, errcode, errmsg, headers, fp)
    else:
      FancyURLopener.http_error_default(url, fp, errcode, errmsg, headers)

class DummyOmap(object):
  def remap(self, addr):
    return addr

#--------------------------------------------------------------------------------
# symbol resolution classes
#--------------------------------------------------------------------------------

class Address(object):
  def __init__(self, mod):
    self.module_name = str(mod.BaseDllName)
    self.limit = int(mod.SizeOfImage)
    self.parser = NameParser()

class FunctionAddress(Address):
  def __init__(self, mod, ordinal, func_rva, func_name):
    assert func_rva != None
    Address.__init__(self, mod)
    self.address = int(func_rva)
    if func_name == None:
      self.name = str(ordinal or '')
    else:
      self.name = str(self.parser.undecorate(str(func_name))[0])

  def __repr__(self):
    return "{0}!{1}".format(self.module_name, self.name)

class SymbolAddress(Address):
  def __init__(self, mod, pdbfile, func_rva, func_name):
    Address.__init__(self, mod)
    self.module_name = pdbfile
    self.address = int(func_rva)
    self.name = str(self.parser.undecorate(str(func_name))[0])

  def __repr__(self):
    return "{0}!{1}".format(self.module_name, self.name)

class RebaseAddress(Address):
  def __init__(self, rva, base_addr):
    self.rva = rva
    self.module_name = rva.module_name
    self.limit = int(rva.limit + base_addr)
    self.address = int(rva.address + base_addr)

  def __repr__(self):
    return repr(self.rva)

#--------------------------------------------------------------------------------
# profile modifications  
#--------------------------------------------------------------------------------

class SymbolTable(object):
  def __init__(self, addr_space, use_symbols=False):
    if use_symbols:
      # Used to cache debugging symbol files (Volatility cache storeage area used, but we manage things manually)
      self._cache_sym_path = "{0}/symbols/{1}".format(addr_space._config.CACHE_DIRECTORY, addr_space.profile.__class__.__name__)
      if not os.path.exists(self._cache_sym_path):
        os.makedirs(self._cache_sym_path)

    # Module exports and symbol server data (sans mod_base info.) - dict( (mod_path, mod_name): dict( func_rva: Address ) )
    self.exports_sym_table = {}
    # System module load data - list(mod_path, mod_name, mod_actual_base)
    self.system_modules = []
    # Process/user module load data - dict( pid: list(mod_path, mod_name, mod_actual_base) )
    self.user_modules = {}
    # The actual per process symbol table - dict( pid: sorteddict( func_addr: RebaseAddress ) )
    self.sym_table = {}
    # dict( (mod_path, mod_name): set( mod ) )
    self.module_map = {}

    self.use_symbols = use_symbols
  
    debug.info("Building function symbol tables for kernel space...")
    kdbg = tasks.get_kdbg(addr_space)
    for mod in kdbg.modules():
      self.add_exports(mod)
      self.system_modules.append( (self.module_path(mod), self.module_name(mod), int(mod.DllBase)) )
      self.update_with_debug_symbols(kdbg.obj_vm, mod)
    for eproc in kdbg.processes():
      pid = int(eproc.UniqueProcessId)
      if pid not in self.user_modules.keys():
        self.user_modules[pid] = []
      for mod in eproc.get_load_modules():
        mod_path = self.module_path(mod)
        mod_name = self.module_name(mod)
        if (mod_path, mod_name) not in self.module_map.keys():
          self.module_map[mod_path, mod_name] = set()
        self.module_map[mod_path, mod_name].add(mod)
        self.user_modules[pid].append( (mod_path, mod_name, int(mod.DllBase)) )
        # Symbol server and export process space symbols are added lazily when lookup method is actually called

  def module_name(self, mod):
    # Normalised module name (without base directory)
    return ntpath.normpath(ntpath.normcase(ntpath.basename(str(mod.BaseDllName))))
  
  def module_path(self, mod):
    # Normalised directory path holding module
    # FIXME: should we be performing any shell expansion here (e.g. SystemRoot == c:\\WINDOWS)?
    return ntpath.normpath(ntpath.normcase(ntpath.dirname(str(mod.FullDllName))))

  # TODO: when no symbols is specified, we may need to look in other process spcaes for good module data?
  def add_exports(self, mod):
    mod_path = self.module_path(mod)
    mod_name = self.module_name(mod)
    if (mod_path, mod_name) not in self.exports_sym_table:
      # First time we've seen this module...
      self.exports_sym_table[mod_path, mod_name] = {}
      for ordinal, func_addr, func_name in mod.exports():
        # Here we ignore forwarded exports as no function address resolves to them!
        if func_addr != None:
          item = FunctionAddress(mod, ordinal, func_addr, func_name)
          self.exports_sym_table[mod_path, mod_name][item.address] = item
    else:
      debug.debug("Encountered module {0} multiple times!".format(mod_name))

  # Following is based on code taken from [3]:
  #   https://code.google.com/p/pdbparse/source/browse/trunk/pdbparse/symlookup.py
  def update_with_debug_symbols(self, addr_space, mod):
    def is_valid_debug_dir(debug_dir, image_base, addr_space):
      return debug_dir != None and debug_dir.AddressOfRawData != 0 and addr_space.is_valid_address(image_base + debug_dir.AddressOfRawData) and   addr_space.is_valid_address(image_base + debug_dir.AddressOfRawData + debug_dir.SizeOfData - 1)
  
    if not self.use_symbols:
      return
    mod_path = self.module_path(mod)
    mod_name = self.module_name(mod)
    image_base = mod.DllBase
    debug_dir = mod.get_debug_directory()
    if not is_valid_debug_dir(debug_dir, image_base, addr_space):
      # No joy in this process space, search other process spaces in order to locate alternative (valid) debugging data
      if (mod_path, mod_name) not in self.module_map.keys():
        # No alternative debug directories, so return
        return
      for alt_mod in self.module_map[mod_path, mod_name]:
        if alt_mod == mod:
          continue
        debug_dir = alt_mod.get_debug_directory()
        if is_valid_debug_dir(debug_dir, alt_mod.DllBase, alt_mod.obj_vm):
          # Got one! Need to update environment variables appropriately
          mod = alt_mod
          addr_space = alt_mod.obj_vm
          mod_path = self.module_path(mod)
          mod_name = self.module_name(mod)
          image_base = mod.DllBase
          break
      if not is_valid_debug_dir(debug_dir, image_base, addr_space):
        # We were unable to locate any valid debug directories, so return
        return
    if debug_dir.Type != 2: # IMAGE_DEBUG_TYPE_CODEVIEW
      return
    debug_data = addr_space.zread(image_base + debug_dir.AddressOfRawData, debug_dir.SizeOfData)
    if debug_data[:4] == 'RSDS':
      guid, filename = pdbparse.peinfo.get_rsds(debug_data)
    elif debug_data[:4] == 'NB10':
      guid, filename = pdbparse.peinfo.get_nb10(debug_data)
    else:
      debug.warning("'{0}' is an unknown CodeView section".format(debug_data[:4]))
      return
    if filename == '':
      return
    # We have valid CodeView debugging information, so try and download PDB file from a symbol server
    saved_mod_path = self._cache_sym_path + os.sep + guid + os.sep + filename
    # Only preform rechecks for downloads every RETRY_TIMEOUT hours
    if not os.path.exists(saved_mod_path + ".ts") or (not os.path.exists(saved_mod_path) and time.time() - os.path.getmtime(saved_mod_path + ".ts") >  RETRY_TIMEOUT * 60 * 60):
      if not os.path.exists(os.path.dirname(saved_mod_path)):
        os.makedirs(os.path.dirname(saved_mod_path))
      self.download_pdbfile(guid.upper(), filename, os.path.dirname(saved_mod_path))
      self.touch(saved_mod_path + ".ts")
    # At this point, and if all has gone well, known co-ords should be: mod; image_base; guid; filename
    if not os.path.exists(self._cache_sym_path + os.sep + guid + os.sep + filename):
      debug.warning("Symbols for module {0} (in {1}) not found".format(mod.BaseDllName, filename))
      return
    pdbname = self._cache_sym_path + os.sep + guid + os.sep + filename
  
    try:
      # Do this the hard way to avoid having to load
      # the types stream in mammoth PDB files
      pdb = pdbparse.parse(pdbname, fast_load=True)
      pdb.STREAM_DBI.load()
      pdb._update_names()
      pdb.STREAM_GSYM = pdb.STREAM_GSYM.reload()
      pdb.STREAM_GSYM.load()
      pdb.STREAM_SECT_HDR = pdb.STREAM_SECT_HDR.reload()
      pdb.STREAM_SECT_HDR.load()
      # These are the dicey ones
      pdb.STREAM_OMAP_FROM_SRC = pdb.STREAM_OMAP_FROM_SRC.reload()
      pdb.STREAM_OMAP_FROM_SRC.load()
      pdb.STREAM_SECT_HDR_ORIG = pdb.STREAM_SECT_HDR_ORIG.reload()
      pdb.STREAM_SECT_HDR_ORIG.load()
    except AttributeError:
      pass
  
    try:
      sects = pdb.STREAM_SECT_HDR_ORIG.sections
      omap = pdb.STREAM_OMAP_FROM_SRC
    except AttributeError:
      # In this case there is no OMAP, so we use the given section
      # headers and use the identity function for omap.remap
      sects = pdb.STREAM_SECT_HDR.sections
      omap = DummyOmap()
    gsyms = pdb.STREAM_GSYM
  
    for sym in gsyms.globals:
      if not hasattr(sym, 'offset'): 
        continue
      off = sym.offset
      try:
        virt_base = sects[sym.segment-1].VirtualAddress
      except IndexError:
        continue
  
      sym_rva = omap.remap(off+virt_base)
      item = SymbolAddress(mod, filename, sym_rva, sym.name)
      if (mod_path, mod_name) not in self.exports_sym_table.keys():
        self.exports_sym_table[mod_path, mod_name] = {}
      # We intentionally overwrite function exports data with more "accurate" debug symbols information
      self.exports_sym_table[mod_path, mod_name][item.address] = item

  lastprog = None
  def progress(self, blocks, blocksz, totalsz):
    if self.lastprog == None:
        debug.info("Connected. Downloading data...")
    percent = int((100*(blocks*blocksz)/float(totalsz)))
    if self.lastprog != percent and percent % 5 == 0: 
      debug.info("{0}%".format(percent))
    self.lastprog = percent
  
  def download_pdbfile(self, guid, filename, path):
    for sym_url in SYM_URLS:
      url = "{0}/{1}/{2}/".format(sym_url, filename, guid)
      proxy = urllib2.ProxyHandler()
      opener = urllib2.build_opener(proxy)
      tries = [ filename[:-1] + '_', filename ]
      for t in tries:
        debug.info("Trying {0}".format(url+t))
        outfile = os.path.join(path, t)
        try:
          PDBOpener().retrieve(url+t, outfile, reporthook=self.progress)
          debug.info("Downloaded symbols and cached at {0}".format(outfile))
          if t.endswith("_"):
            self.cabextract(outfile, path)
            debug.info("Unpacked download into {0}".format(path))
            os.remove(outfile)
          return
        except urllib2.HTTPError, e:
          debug.warning("HTTP error {0}".format(e.code))
    debug.warning("failed to download debugging symbols for {0}".format(filename))
  
  # This function is used to keep track of attempts at file downloading
  def touch(self, path):
    now = time.time()
    try:
      os.utime(path, (now, now))
    except os.error:
      if not os.path.exists(os.path.dirname(path)):
        os.makedirs(os.path.dirname(path))
      open(path, "w").close()
      os.utime(path, (now, now))

  cabsetup = None
  def cabextract(self, filename, path):
    def _cabextract(filename, path):
      os.system("cabextract -d{0} {1}".format(path, filename))
    def _7z(filename, path):
      os.system("7z -o{0} e {1}".format(path, filename))
  
    if self.cabsetup != None:
      self.cabsetup(filename, path)
      return
    for cabfunc in ["_cabextract", "_7z"]:
      try:
        self.cabsetup = locals()[cabfunc]
        self.cabsetup(filename, path)
        return
      except:
        pass
    debug.error("could not unpack the downloaded CAB file - please install cabextract or 7z")

class SymbolsEPROCESS(windows._EPROCESS):
  _symbol_table = None
  def symbol_table(self, use_symbols=False):
    """
    Returns the SymbolTable object instance used to hold symbol information. If the current 
    process has not been previously seen, then symbol information is added to the returned 
    object instance.

    If the use_symbols option is True, then Microsoft's debugging symbol information is used.
    """
    if use_symbols and not pdbparse_installed:
      raise ValueError("pdbparse (>= 1.1 [r104]) needs to be installed in order to use --symbols")

    if SymbolsEPROCESS._symbol_table == None:
      SymbolsEPROCESS._symbol_table = SymbolTable(self.get_process_address_space(), use_symbols)
  
    pid = int(self.UniqueProcessId)
    if pid not in SymbolsEPROCESS._symbol_table.sym_table.keys():
      debug.info("Building function symbol tables for PID {0}...".format(pid))
      for mod in self.get_load_modules():
        SymbolsEPROCESS._symbol_table.add_exports(mod)
        SymbolsEPROCESS._symbol_table.update_with_debug_symbols(self.get_process_address_space(), mod)
    
      sym_table = sorteddict()
      for mod_path, mod_name, mod_base in SymbolsEPROCESS._symbol_table.system_modules + SymbolsEPROCESS._symbol_table.user_modules[pid]:
        for func_addr, func_rva in SymbolsEPROCESS._symbol_table.exports_sym_table[mod_path, mod_name].items():
          item = RebaseAddress(func_rva, mod_base)
          sym_table[func_addr+mod_base] = item
      SymbolsEPROCESS._symbol_table.sym_table[pid] = sym_table
    return SymbolsEPROCESS._symbol_table

  def lookup(self, addr, use_symbols=False):
    """
    Resolves addr to the nearest function/method name within this processes symbol table. 

    When the use_symbols option is True, symbol tables are built using Microsoft's 
    debugging symbol information. The symbol PDB files are downloaded and cached within 
    Volatility's caching directories.
    
    If use_symbols is False or no symbol information is available, then module exports 
    information is used to populate the symbols tables.
    """
    if use_symbols and not pdbparse_installed:
      raise ValueError("pdbparse (>= 1.1 [r104]) needs to be installed in order to use PDB symbol information")

    if addr == None:
      return "-"

    func_name = "UNKNOWN"
    sym_table = self.symbol_table(use_symbols=use_symbols).sym_table[int(self.UniqueProcessId)]
    idx = sym_table.viewkeys().bisect_right(addr) - 1
    if 0 <= idx:
      nearest_addr = sym_table.viewkeys()[idx]
      if addr < sym_table[nearest_addr].limit:
        # addr is within a loaded module address space
        func_name = repr(sym_table[nearest_addr])
        diff = addr - nearest_addr
        if diff != 0:
          func_name = "{0}{1:+#x}".format(func_name, diff)
    if use_symbols:
      return func_name
    return "????/{0}".format(func_name)

class SymbolsModification(obj.ProfileModification):
  before = ["WindowsObjectClasses"]

  conditions = {'os': lambda x: x == 'windows'}

  def modification(self, profile):
    for func in SymbolsEPROCESS.__dict__:
      if isfunction(SymbolsEPROCESS.__dict__[func]):
        setattr(profile.object_classes['_EPROCESS'], func, SymbolsEPROCESS.__dict__[func])

#--------------------------------------------------------------------------------
# main plugin code
#--------------------------------------------------------------------------------

class Symbols(commands.Command):
  """
  Symbols objects are used to resolve addresses (e.g. functions, methods, etc.) using 
  Microsoft's debugging symbols (i.e. PDB files). Name resolution is performed (via the
   lookup method) relative to a given processes address space.

  When pdbparse is installed, addresses can resolve to names with the format:

      module.pdb!name+0x0FF

  When pdbparse is *not* installed, we failover to using export symbols from the owning 
  module. In which case, addresses resolve to names with the format:

      ????/module!name+0x0FF

  Here ???? indicates that debugging symbols could not be consulted during the name resolution 
  process.

  When names can not be resolved, they resolve to UNKNOWN. The null address resolves 
  to '-'.
  """

  def __init__(self, config, *args, **kwargs):
    commands.Command.__init__(self, config, *args, **kwargs)
    config.add_option("SYMBOLS", default = False, action = 'store_true', cache_invalidator = False, help = "Use symbol servers to resolve process addresses to module names")

    self.kdbg = tasks.get_kdbg(utils.load_as(config))
    self.use_symbols = getattr(config, 'SYMBOLS', False)
    if self.use_symbols and not pdbparse_installed:
      debug.error("pdbparse (>= 1.1 [r104]) needs to be installed in order to use --symbols")

  def render_text(self, outfd, data):
    self.table_header(outfd, [
      ('Process ID', '<16'),
      ('Module', '<16'),
      ("Function Address", '<16'),
      ("Function Name", "<")
    ])
    for eproc in self.kdbg.processes():
      sym_obj = eproc.symbol_table(use_symbols=self.use_symbols)
      for func_addr, sym in sym_obj.sym_table[int(eproc.UniqueProcessId)].items():
        self.table_row(outfd, int(eproc.UniqueProcessId), sym.module_name, "{0:#010x}".format(func_addr), repr(sym))
