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
This code is designed to resolve addresses or symbol names. 

Use --build_symbols to build the *initial* SQLite database for the current profile.

When the --use_symbols option is specified, then Microsoft's debugging symbol 
information is used to perform lookups. The symbol PDB files are downloaded and 
processed into SQLite3 DB entries that are saved within Volatility's caching 
directories.

If --use_symbols is *not* specified, then module exports information is used to 
resolve lookups.

@author:       Carl Pulley
@license:      GNU General Public License 2.0 or later
@contact:      c.j.pulley@hud.ac.uk

DEPENDENCIES:
  construct (pdbparse dependency)
  pdbparse (along with cabextract or 7z) - need to install >= 1.1 [>= r104]
  pefile (pdbparse dependency)
  sqlite3

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
[6] Wine (2006). pdb.c source file from the winedump tool. Retrieved 12/Aug/2013 from:
      http://source.winehq.org/source/tools/winedump/pdb.c
[7] Schreiber, S. B. (2001). Undocumented Windows 2000 Secrets: A Programmers Cookbook. 
    Addison-Wesley. ISBN 0-201-72187-2.
"""

try:
  import construct
except ImportError:
  debug.error("construct (a pdbparse dependency) needs to be installed in order to use the symbols plugin/code")
try:
  import pdbparse
  import pdbparse.peinfo
  from pdbparse.undecorate import undecorate as msvc_undecorate
  from pdbparse.undname import undname as msvcpp_undecorate
except ImportError:
  debug.error("pdbparse (>= 1.1 [r104]) needs to be installed in order to use the symbols plugin/code")
from inspect import isfunction
import ntpath
import os
import re
import shutil
import sqlite3
import sys
import time
import tempfile
from urllib import FancyURLopener
import urllib2
import volatility.commands as commands
import volatility.debug as debug
import volatility.obj as obj
import volatility.plugins.overlays.windows.windows as windows
import volatility.utils as utils
import volatility.win32.tasks as tasks

# URLs to query when searching for debugging symbols
SYM_URLS = [ 'http://msdl.microsoft.com/download/symbols', 'http://symbols.mozilla.org/firefox', 'http://chromium-browser-symsrv.commondatastorage.googleapis.com' ]

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
# profile modifications  
#--------------------------------------------------------------------------------

class SymbolTable(object):
  def __init__(self, addr_space, build_symbols):
    self.parser = NameParser()

    # Used to cache symbol/export/module information in an SQLite3 DB
    # NB: Volatility cache storeage area used, but we manage things manually.
    cache_sym_db_path = "{0}/symbols".format(addr_space._config.CACHE_DIRECTORY)
    if not os.path.exists(cache_sym_db_path):
      os.makedirs(cache_sym_db_path)
    self._sym_db_conn = sqlite3.connect("{0}/{1}.db".format(cache_sym_db_path, addr_space.profile.__class__.__name__))
    db = self.get_cursor()
    db.execute("attach ':memory:' as volatility")
    self._sym_db_conn.commit()

    kdbg = tasks.get_kdbg(addr_space)

    # Build tables and indexes
    self.create_tables(db)

    # Insert kernel space module information
    debug.info("Building function symbol tables for kernel space...")
    for mod in kdbg.modules():
      if build_symbols:
        # Module row created by add_exports if it doesn't already exist
        self.add_exports(db, mod)
        self.add_debug_symbols(db, kdbg.obj_vm, mod)
      # Link in system modules to each process
      for eproc in kdbg.processes():
        self.add_module(db, eproc, mod)

    # Insert (per process) user space module information
    debug.info("Building function symbol tables for each processes user space...")
    for eproc in kdbg.processes():
      debug.info("Processing PID {0} ...".format(int(eproc.UniqueProcessId)))
      for mod in eproc.get_load_modules():
        if build_symbols:
          # Module row created by add_exports if it doesn't already exist
          self.add_exports(db, mod)
          self.add_debug_symbols(db, eproc.get_process_address_space(), mod)
        # Link in user module to current process
        self.add_module(db, eproc, mod)

    debug.info("Symbol tables successfully built")

  def __del__(self):
    self._sym_db_conn.close()

  def create_tables(self, db):
    """
    Class Diagram
    =============

    ....................
    :                  :
    : process *---------* module *-------* pdb -------* symbol
    :             |    :    |        |      |
    :            base  :    *     mod_pdb   *
    ....................  export          frame
    In-memory tables                        ^
                                            |
                                        +---+---+
                                        |       |
                                       fpo    fpov2
    """

    db.execute("""CREATE TABLE IF NOT EXISTS module (
      id INTEGER PRIMARY KEY, 
      name TEXT NOT NULL,
      mpath TEXT NOT NULL,
      mlimit INTEGER NOT NULL,
      UNIQUE(mpath, name)
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS module_name ON module(name)")

    db.execute("""CREATE TABLE IF NOT EXISTS export (
      id INTEGER PRIMARY KEY,  
      module_id INTEGER NOT NULL, 
      ordinal INTEGER,
      name TEXT,
      rva INTEGER NOT NULL,
      FOREIGN KEY(module_id) REFERENCES module(id)
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS export_name ON export(name)")
    db.execute("CREATE INDEX IF NOT EXISTS export_rva ON export(rva)")
    db.execute("CREATE INDEX IF NOT EXISTS export_mod_rva ON export(module_id, rva)")

    db.execute("""CREATE TABLE IF NOT EXISTS mod_pdb (
      id INTEGER PRIMARY KEY,  
      module_id INTEGER NOT NULL,
      pdb_id INTEGER NOT NULL,
      FOREIGN KEY(module_id) REFERENCES module(id),
      FOREIGN KEY(pdb_id) REFERENCES pdb(id)
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS mod_pdb_link ON mod_pdb(module_id, pdb_id)")

    db.execute("""CREATE TABLE IF NOT EXISTS pdb (
      id INTEGER PRIMARY KEY,
      file TEXT NOT NULL,
      guid TEXT,
      src TEXT,
      downloaded_at TEXT,
      UNIQUE(guid, file, src)
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS pdb_file_guid ON pdb(file, guid)")

    db.execute("""CREATE TABLE IF NOT EXISTS symbol (
      id INTEGER PRIMARY KEY, 
      pdb_id INTEGER NOT NULL, 
      type INTEGER NOT NULL,
      section TEXT NOT NULL,
      name TEXT NOT NULL,
      rva INTEGER NOT NULL,
      FOREIGN KEY(pdb_id) REFERENCES pdb(id)
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS symbol_name ON symbol(section, name)")
    db.execute("CREATE INDEX IF NOT EXISTS symbol_rva ON symbol(rva)")
    db.execute("CREATE INDEX IF NOT EXISTS symbol_pdb_rva ON symbol(pdb_id, rva)")

    # Single table inheritance usage:
    #
    # table_name == "fpo":
    #   NULL entries: max_stack; flags; program_string
    #   non-NULL entries: frame; has_seh; use_bp
    # table_name == "fpov2":
    #   NULL entries: frame; has_seh; use_bp
    #   non-NULL entries: max_stack; flags; program_string
    db.execute("""CREATE TABLE IF NOT EXISTS frame (
      id INTEGER PRIMARY KEY, 
      pdb_id INTEGER NOT NULL, 
      table_name TEXT NOT NULL,
      off_start INTEGER NOT NULL,
      proc_size INTEGER NOT NULL,
      locals INTEGER NOT NULL,
      params INTEGER NOT NULL,
      prolog INTEGER NOT NULL,
      saved_regs INTEGER NOT NULL,
      frame TEXT,
      has_seh INTEGER,
      use_bp INTEGER,
      max_stack INTEGER,
      flags INTEGER,
      program_string TEXT,
      FOREIGN KEY(pdb_id) REFERENCES pdb(id)
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS frame_child ON frame(table_name)")

    db.execute("""CREATE TABLE IF NOT EXISTS volatility.process (
      id INTEGER PRIMARY KEY, 
      eproc INTEGER NOT NULL,
      UNIQUE (eproc)
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS volatility.eproc_addr ON process(eproc)")

    db.execute("""CREATE TABLE IF NOT EXISTS volatility.base (
      id INTEGER PRIMARY KEY,  
      process_id INTEGER NOT NULL, 
      module_id INTEGER NOT NULL,
      addr INTEGER NOT NULL,
      FOREIGN KEY(process_id) REFERENCES process(id),
      FOREIGN KEY(module_id) REFERENCES module(id)
    )""")
    db.execute("CREATE INDEX IF NOT EXISTS volatility.base_link ON base(process_id, module_id)")

    self._sym_db_conn.commit()

  def get_cursor(self):
    return self._sym_db_conn.cursor()

  def module_name(self, mod):
    # Normalised module name (without base directory)
    return ntpath.normpath(ntpath.normcase(ntpath.basename(str(mod.BaseDllName))))
  
  def module_path(self, mod):
    # Normalised directory path holding module
    # FIXME: should we be performing any shell expansion here (e.g. SystemRoot == c:\\WINDOWS)?
    return ntpath.normpath(ntpath.normcase(ntpath.dirname(str(mod.FullDllName))))

  def module_id(self, db, mod):
    mod_path = self.module_path(mod)
    mod_name = self.module_name(mod)

    db.execute("SELECT id FROM module WHERE mpath=? AND name=?", (mod_path, mod_name))
    row = db.fetchone()
    if row == None:
      mod_name = self.module_name(mod)
      mod_path = self.module_path(mod)
      mod_limit = int(mod.SizeOfImage)
      db.execute("INSERT INTO module(name, mpath, mlimit) VALUES (?, ?, ?)", (mod_name, mod_path, mod_limit))
      self._sym_db_conn.commit()
      db.execute("SELECT LAST_INSERT_ROWID() FROM module")
      row = db.fetchone()

    return row[0]

  def process_id(self, db, eproc):
    eproc_addr = int(eproc.v())
    db.execute("SELECT id FROM volatility.process WHERE eproc=?", (eproc_addr,))
    row = db.fetchone()
    if row == None:
      db.execute("INSERT INTO volatility.process(eproc) VALUES (?)", (eproc_addr,))
      self._sym_db_conn.commit()
      db.execute("SELECT LAST_INSERT_ROWID() FROM volatility.process")
      row = db.fetchone()

    return row[0]

  def do_download(self, db, module_id, guid, filename):
    db.execute("""SELECT * 
      FROM mod_pdb
        INNER JOIN pdb ON pdb_id=pdb.id 
      WHERE module_id=? 
        AND guid=? 
        AND file=? 
        AND downloaded_at IS NOT NULL
    """, (module_id, str(guid.upper()).rstrip('\0'), str(filename).rstrip('\0')))
    row = db.fetchone()
    if row == None:
      return True
    return False

  def lookup_name(self, eproc, addr, use_symbols):
    def export_lookup(db, module_name, module_id, module_base, section_pad):
      db.execute("""SELECT rva
        FROM export 
        WHERE module_id = :module_id 
          AND rva <= :addr
      """, { "module_id": module_id, "addr": addr - module_base })
      row = db.fetchone()
      if row == None or row[0] == None:
        return [ (module_name, section_pad, None, addr - module_base) ]
      minimal_rva = row[0]

      db.execute("""SELECT MAX(rva)
        FROM export 
        WHERE module_id = :module_id 
          AND :minimal_rva <= rva
          AND rva <= :addr
      """, { "module_id": module_id, "minimal_rva": minimal_rva, "addr": addr - module_base })
      row = db.fetchone()
      max_rva = row[0]
      assert(max_rva != None)

      db.execute("""SELECT DISTINCT ordinal, name, :addr - rva
        FROM export 
        WHERE module_id = :module_id 
          AND rva = :max_rva
      """, { "module_id": module_id, "addr": addr - module_base, "max_rva": max_rva })
      row = db.fetchall()
      assert(len(row) > 0)
      result = []
      for ordinal, func_name, diff in row:
        if func_name == "":
          func_name = str(ordinal or '')
        result += [ (module_name, section_pad, func_name, diff) ]
      return result

    db = self.get_cursor()
    eproc_addr = int(eproc.v())

    # Locate the module our address may reside in
    db.execute("""SELECT DISTINCT module.id, module.name, base.addr
      FROM volatility.process AS process
        INNER JOIN volatility.base AS base ON base.process_id = process.id 
        INNER JOIN module ON base.module_id = module.id 
      WHERE process.eproc = :eproc
        AND base.addr <= :addr 
        AND :addr < base.addr + module.mlimit
    """, { "eproc": eproc_addr, "addr": addr })
    row = db.fetchall()
    if len(row) == 0:
      return []
    assert(len(row) == 1)
    module_id, module_name, module_base = row[0]

    # Locate the module's symbol range our address may reside in
    if use_symbols:
      db.execute("""SELECT pdb.id
        FROM mod_pdb
          INNER JOIN pdb ON mod_pdb.pdb_id = pdb.id
          INNER JOIN symbol ON pdb.id = symbol.pdb_id
        WHERE module_id = :module_id 
          AND rva <= :addr
      """, { "module_id": module_id, "addr": addr - module_base })
      row = db.fetchone()
      if row == None or row[0] == None:
        return export_lookup(db, module_name, module_id, module_base, "")
      pdb_id = row[0]

      db.execute("""SELECT MAX(rva)
        FROM pdb
          INNER JOIN symbol ON pdb.id = symbol.pdb_id
        WHERE pdb.id = :pdb_id
          AND rva <= :addr
      """, { "pdb_id": pdb_id, "addr": addr - module_base })
      row = db.fetchone()
      max_rva = row[0]
      assert(max_rva != None)

      db.execute("""SELECT DISTINCT section, name, :addr - rva
        FROM pdb
          INNER JOIN symbol ON pdb.id = symbol.pdb_id
        WHERE pdb.id = :pdb_id 
          AND rva = :max_rva
      """, { "pdb_id": pdb_id, "addr": addr - module_base, "max_rva": max_rva })
      row = db.fetchall()
      assert(len(row) > 0)
      
      return [ (module_name, section_name, func_name, diff) for section_name, func_name, diff in row ]
    else:
      return export_lookup(db, module_name, module_id, module_base, "????")

  # TODO: implement mapping from name to decorated form?
  def lookup_addr(self, eproc, name, section, module, use_symbols):
    db = self.get_cursor()
    
    if use_symbols:
      if section != None and module != None:
        sql_query = """SELECT base.addr + rva 
          FROM symbol
            INNER JOIN pdb ON symbol.pdb_id = pdb.id 
            INNER JOIN mod_pdb ON mod_pdb.pdb_id = pdb.id
            INNER JOIN module ON mod_pdb.module_id = module.id
            INNER JOIN volatility.base AS base ON base.module_id = module.id 
            INNER JOIN volatility.process AS process ON base.process_id = process.id 
          WHERE section LIKE :section 
            AND module.name LIKE :module
            AND symbol.name LIKE :name 
            AND process.eproc = :eproc
        """
        sql_vars = { "eproc": int(eproc.v()), "name": name, "section": section, "module": module }
      elif section == None and module != None:
        sql_query = """SELECT base.addr + rva 
          FROM symbol
            INNER JOIN pdb ON symbol.pdb_id = pdb.id 
            INNER JOIN mod_pdb ON mod_pdb.pdb_id = pdb.id
            INNER JOIN module ON mod_pdb.module_id = module.id
            INNER JOIN volatility.base AS base ON base.module_id = module.id 
            INNER JOIN volatility.process AS process ON base.process_id = process.id 
          WHERE module.name LIKE :module
            AND symbol.name LIKE :name 
            AND process.eproc = :eproc
        """
        sql_vars = { "eproc": int(eproc.v()), "name": name, "module": module }
      elif section != None and module == None:
        sql_query = """SELECT base.addr + rva 
          FROM symbol
            INNER JOIN pdb ON symbol.pdb_id = pdb.id 
            INNER JOIN mod_pdb ON mod_pdb.pdb_id = pdb.id
            INNER JOIN module ON mod_pdb.module_id = module.id
            INNER JOIN volatility.base AS base ON base.module_id = module.id 
            INNER JOIN volatility.process AS process ON base.process_id = process.id 
          WHERE section LIKE :section 
            AND symbol.name LIKE :name 
            AND process.eproc = :eproc
        """
        sql_vars = { "eproc": int(eproc.v()), "name": name, "section": section }
      else:
        sql_query = """SELECT base.addr + rva 
          FROM symbol
            INNER JOIN pdb ON symbol.pdb_id = pdb.id 
            INNER JOIN mod_pdb ON mod_pdb.pdb_id = pdb.id
            INNER JOIN module ON mod_pdb.module_id = module.id
            INNER JOIN volatility.base AS base ON base.module_id = module.id 
            INNER JOIN volatility.process AS process ON base.process_id = process.id 
          WHERE symbol.name LIKE :name 
            AND process.eproc = :eproc
        """
        sql_vars = { "eproc": int(eproc.v()), "name": name }
    else:
      if module != None:
        sql_query = """SELECT base.addr + rva 
          FROM export
            INNER JOIN module ON export.module_id = module.id 
            INNER JOIN volatility.base AS base ON base.module_id = module.id 
            INNER JOIN volatility.process AS process ON base.process_id = process.id 
          WHERE export.name LIKE :name 
            AND module.name LIKE :module
            AND process.eproc = :eproc
        """
        sql_vars = { "eproc": int(eproc.v()), "name": name, "module": module }
      else:
        sql_query = """SELECT base.addr + rva 
          FROM export
            INNER JOIN module ON export.module_id = module.id 
            INNER JOIN volatility.base AS base ON base.module_id = module.id 
            INNER JOIN volatility.process AS process ON base.process_id = process.id 
          WHERE export.name LIKE :name 
            AND process.eproc = :eproc
        """
        sql_vars = { "eproc": int(eproc.v()), "name": name }

    return [ row[0] for row in db.execute(sql_query, sql_vars) ]

  def add_module(self, db, eproc, mod):
    process_id = self.process_id(db, eproc)
    module_id = self.module_id(db, mod)
    mod_base = int(mod.DllBase)
    db.execute("SELECT * FROM volatility.base WHERE addr=? AND process_id=? AND module_id=?", (mod_base, process_id, module_id))
    row = db.fetchone()
    if row == None:
      # Not previously seen this process/module addressing relationship
      db.execute("INSERT INTO volatility.base(addr, process_id, module_id) VALUES (?, ?, ?)", (mod_base, process_id, module_id))
    self._sym_db_conn.commit()

  def add_exports(self, db, mod):
    module_id = self.module_id(db, mod)    

    for ordinal, func_addr, func_name in mod.exports():
      # FIXME: when mapping names to addresses, is this correct behaviour?
      # Here we ignore forwarded exports as no symbol address should resolve to them!
      if func_addr != None:
        db.execute("SELECT name FROM export WHERE module_id=? AND rva=?", (module_id, int(func_addr)))
        row = db.fetchone()
        if row == None:
          # We've not previously seen this function export
          db.execute("INSERT INTO export(module_id, ordinal, name, rva) VALUES (?, ?, ?, ?)", (module_id, int(ordinal), str(func_name or '').rstrip('\0'), int(func_addr)))
        else:
          # Only update if the function name is currently unknown (i.e. it was previously referred to via an ordinal)
          old_func_name = row[0]
          if old_func_name == '' and func_name != None:
            db.execute("UPDATE export SET name=? WHERE module_id=? AND rva=?", (str(func_name).rstrip('\0'), module_id, int(func_addr)))

    self._sym_db_conn.commit()

  # Following is based on code taken from [3]:
  #   https://code.google.com/p/pdbparse/source/browse/trunk/pdbparse/symlookup.py
  def add_debug_symbols(self, db, addr_space, mod):
    def is_valid_debug_dir(debug_dir, image_base, addr_space):
      return debug_dir != None and debug_dir.AddressOfRawData != 0 and addr_space.is_valid_address(image_base + debug_dir.AddressOfRawData) and addr_space.is_valid_address(image_base + debug_dir.AddressOfRawData + debug_dir.SizeOfData - 1)
  
    mod_path = self.module_path(mod)
    mod_name = self.module_name(mod)
    module_id = self.module_id(db, mod)
    image_base = mod.DllBase
    debug_dir = mod.get_debug_directory()
    if not is_valid_debug_dir(debug_dir, image_base, addr_space):
      # No joy in this process space
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
    saved_mod_path = tempfile.gettempdir() + os.sep + guid
    if self.do_download(db, module_id, guid, filename):
      if not os.path.exists(saved_mod_path):
        os.makedirs(saved_mod_path)
      self.download_pdbfile(db, guid.upper(), module_id, filename, saved_mod_path)
      # At this point, and if all has gone well, known co-ords should be: mod; image_base; guid; filename
      pdbname = saved_mod_path + os.sep + filename
      if not os.path.exists(pdbname):
        shutil.rmtree(saved_mod_path)
        debug.warning("Symbols for module {0} (in {1}) not found".format(mod.BaseDllName, filename))
        return
    
      try:
        # Do this the hard way to avoid having to load
        # the types stream in mammoth PDB files
        pdb = pdbparse.parse(pdbname, fast_load=True)
        pdb.STREAM_DBI.load()
        # As pdbparse doesn't add STREAM_FPO_STRINGS to parent, do it manually
        if pdb.STREAM_DBI.DBIDbgHeader.snNewFPO != -1:
          pdb.add_supported_stream("STREAM_FPO_STRINGS", pdb.STREAM_DBI.DBIDbgHeader.snNewFPO+1, pdbparse.PDBFPOStrings)
      except AttributeError:
        pass

      try:
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
        # Ensure FPO streams are loaded
        pdb.STREAM_FPO = pdb.STREAM_FPO.reload()
        pdb.STREAM_FPO.load()
        pdb.STREAM_FPO_NEW = pdb.STREAM_FPO_NEW.reload()
        pdb.STREAM_FPO_NEW.load()
        pdb.STREAM_FPO_STRINGS = pdb.STREAM_FPO_STRINGS.reload()
        pdb.STREAM_FPO_STRINGS.load()
        pdb.STREAM_FPO_NEW.load2() # inject program strings
      except AttributeError:
        pass
      except construct.adapters.ConstError as err:
        # TODO: fix actual PDB parsing failure issue!
        debug.warning("Ignoring PDB parsing failure of {0}/{1}: {2}".format(guid.upper(), filename, err.message))

      db.execute("""SELECT pdb.id 
        FROM mod_pdb
          INNER JOIN pdb ON pdb_id=pdb.id 
        WHERE module_id=? 
          AND guid=? 
          AND file=?
      """, (module_id, str(guid.upper()).rstrip('\0'), str(filename).rstrip('\0')))
      row = db.fetchone()
      assert(row != None)
      pdb_id = row[0]

      self.process_gsyms(db, pdb, pdb_id, module_id, guid, filename)
      try:
        self.process_fpo(db, pdb, pdb_id, module_id, guid, filename)
      except AttributeError:
        pass
      try:
        self.process_fpov2(db, pdb, pdb_id, module_id, guid, filename)
      except AttributeError:
        pass

      shutil.rmtree(saved_mod_path)
      debug.info("Removed directory {0} and its contents".format(saved_mod_path))
      self._sym_db_conn.commit()

  def process_gsyms(self, db, pdb, pdb_id, module_id, guid, filename):
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
        section = sects[sym.segment-1].Name
      except IndexError:
        continue
    
      sym_rva = omap.remap(off+virt_base)
  
      db.execute("INSERT INTO symbol(pdb_id, type, section, name, rva) VALUES (?, ?, ?, ?, ?)", (pdb_id, int(sym.symtype), str(section).rstrip('\0'), str(sym.name).rstrip('\0'), int(sym_rva)))

  def process_fpo(self, db, pdb, pdb_id, module_id, guid, filename):
    data_stream = pdb.STREAM_FPO
    for fpo in data_stream.fpo:
      db.execute("""INSERT INTO frame(pdb_id, table_name, off_start, proc_size, locals, params, prolog, saved_regs, frame, has_seh, use_bp) 
        VALUES (:pdb_id, 'fpo', :off_start, :proc_size, :locals, :params, :prolog, :saved_regs, :frame, :has_seh, :use_bp)
      """, { 
        "pdb_id": pdb_id, 
        "off_start": int(fpo.ulOffStart), 
        "proc_size": int(fpo.cbProcSize), 
        "locals": int(fpo.cdwLocals), 
        "params": int(fpo.cdwParams), 
        "prolog": int(fpo.cbProlog), 
        "saved_regs": int(fpo.cbRegs), 
        "frame": int(fpo.cbFrame), 
        "has_seh": int(fpo.fHasSEH), 
        "use_bp": int(fpo.fUseBP) 
      })

  def process_fpov2(self, db, pdb, pdb_id, module_id, guid, filename):
    def flags_to_int(flags):
      return 1*int(flags.SEH) + 2*int(flags.CPPEH) + 4*int(flags.fnStart)

    data_stream = pdb.STREAM_FPO_NEW
    for fpo in data_stream.fpo:
      db.execute("""INSERT INTO frame(pdb_id, table_name, off_start, proc_size, locals, params, prolog, saved_regs, max_stack, flags, program_string) 
        VALUES (:pdb_id, 'fpov2', :off_start, :proc_size, :locals, :params, :prolog, :saved_regs, :max_stack, :flags, :program_string)
      """, { 
        "pdb_id": pdb_id, 
        "off_start": int(fpo.ulOffStart), 
        "proc_size": int(fpo.cbProcSize), 
        "locals": int(fpo.cbLocals), 
        "params": int(fpo.cbParams), 
        "prolog": int(fpo.cbProlog), 
        "saved_regs": int(fpo.cbSavedRegs), 
        "max_stack": int(fpo.maxStack), 
        "flags": flags_to_int(fpo.flags),
        "program_string": str(fpo.ProgramString)
      })

  lastprog = None
  def progress(self, blocks, blocksz, totalsz):
    if self.lastprog == None:
        debug.info("Connected. Downloading data...")
    percent = int((100*(blocks*blocksz)/float(totalsz)))
    if self.lastprog != percent and percent % 5 == 0: 
      debug.info("{0}%".format(percent))
    self.lastprog = percent
  
  def download_pdbfile(self, db, guid, module_id, filename, path):
    db.execute("SELECT id FROM pdb WHERE guid=? AND file=?", (str(guid.upper()).rstrip('\0'), str(filename).rstrip('\0')))
    row = db.fetchone()
    if row == None:
      db.execute("INSERT INTO pdb(guid, file) VALUES (?, ?)", (str(guid.upper()).rstrip('\0'), str(filename).rstrip('\0')))
      db.execute("SELECT LAST_INSERT_ROWID() FROM pdb")
      row = db.fetchone()
    pdb_id = row[0]
    db.execute("SELECT * FROM mod_pdb WHERE module_id=? AND pdb_id=?", (module_id, pdb_id))
    row = db.fetchone()
    if row == None:
      db.execute("INSERT INTO mod_pdb(module_id, pdb_id) VALUES (?, ?)", (module_id, pdb_id))
    self._sym_db_conn.commit()

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
            db.execute("UPDATE pdb SET downloaded_at=DATETIME('now'), src=? WHERE id=? AND guid=? AND file=?", (sym_url, pdb_id, str(guid.upper()).rstrip('\0'), str(filename).rstrip('\0')))
            self._sym_db_conn.commit()
          return
        except urllib2.HTTPError, e:
          debug.warning("HTTP error {0}".format(e.code))
    debug.warning("Failed to download debugging symbols for {0}".format(filename))

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
  def symbol_table(self, build_symbols=False):
    """
    Returns the SymbolTable object instance used to access symbol information from the underlying
    SQLite3 DB.

    If the build_symbols option is True, then the SQLite3 DB will be rebuilt (if it doesn't exist)
    or updated (if it exists).
    """
    if SymbolsEPROCESS._symbol_table == None:
      SymbolsEPROCESS._symbol_table = SymbolTable(self.get_process_address_space(), build_symbols)

    return SymbolsEPROCESS._symbol_table

  def lookup(self, addr_or_name, use_symbols=True):
    """
    When an address is given, resolve to the nearest symbol names within this processes 
    symbol table. If use_symbols is specified, addresses can resolve to names with the 
    format:

      module.pdb/section!name+0x0FF

    If use_symbols is *not* specified, addresses resolve to names with the format:

      module/????!name+0x0FF

    Here, ???? indicates that exports are being used (i.e. an unknown section).

    When a name is given, resolve to the matching symbol name within this processes symbol 
    table and return matching addresses. Symbols/names may be specified using a string 
    matching the format (N.B. '%' can be used as a wild card):

      MODULE/SECTION!NAME

    If use_symbols is True, then resolving occurs using Microsoft's debugging symbol information.
    Otherwise, resolving occurs using the module exports information.
    """
    if addr_or_name == None:
      return None
    elif type(addr_or_name) == int or type(addr_or_name) == long:
      names = self.symbol_table().lookup_name(self, int(addr_or_name), use_symbols)
      result = []
      for module_name, section_name, func_name, diff in names:
        if func_name == None:
          result += [ "{0}/{1}!{2:+#x}".format(module_name, section_name, diff) ]
        else:
          if diff == 0:
            diff = ""
          else:
            diff = "{0:+#x}".format(diff)
          func_name = str(self.symbol_table().parser.undecorate(str(func_name))[0])
          result += [ "{0}/{1}!{2}{3}".format(module_name, section_name, func_name, diff) ]
      return result
    elif type(addr_or_name) == str:
      pattern = re.compile("\A(((?P<module>{0}+)/)?(?P<section>{0}*)!)?(?P<name>{0}+)\Z".format("[a-zA-Z0-9_@\?\$\.%]"))
      mobj = pattern.match(addr_or_name)
      if mobj == None:
        raise ValueError("lookup: symbol name needs to match the format MODULE/SECTION!NAME")
      name = mobj.group("name")
      section = mobj.group("section")
      module = mobj.group("module")
      return self.symbol_table().lookup_addr(self, name, section, module, use_symbols)
    else:
      raise TypeError("lookup: primary argument should be an integer (i.e. an address) or a string (i.e. a symbol name), not of type {0}".format(type(addr_or_name)))

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
  Symbols objects are used to resolve addresses (e.g. functions, methods, etc.) typically 
  using Microsoft's debugging symbols (i.e. PDB files). Name resolution is performed (via 
  the lookup method) relative to a given processes address space.

  When --use_symbols is specified, addresses are resolved using Microsoft's debugging symbols.

  When --use_symbols is *not* specified, address resolution uses the module export symbols.

  NOTE: before using this plugin, it is necessary to first ensure that the symbols table (i.e. an 
    SQLite3 DB) has been built. Use the --build_symbols option for this purpose.
  """

  def __init__(self, config, *args, **kwargs):
    commands.Command.__init__(self, config, *args, **kwargs)
    config.add_option("BUILD_SYMBOLS", default = False, action = 'store_true', cache_invalidator = False, help = "Build symbol table information")
    config.add_option("USE_SYMBOLS", default = False, action = 'store_true', cache_invalidator = False, help = "Use symbol servers to resolve process addresses to module names")

    self.kdbg = tasks.get_kdbg(utils.load_as(config))
    self.build_symbols = getattr(config, 'BUILD_SYMBOLS', False)
    self.use_symbols = getattr(config, 'USE_SYMBOLS', False)

  def render_text(self, outfd, data):
    self.table_header(outfd, [
      ('Process ID', '<16'),
      ('Module', '<16'),
      ('Section', '<16'),
      ("Symbol Address", '<16'),
      ("Symbol Name", "<")
    ])
    parser = NameParser()
    for eproc in self.kdbg.processes():
      pid = int(eproc.UniqueProcessId)
      eproc_addr = int(eproc.v())
      sym_obj = eproc.symbol_table(build_symbols=self.build_symbols)
      db = sym_obj.get_cursor()

      if self.use_symbols:
        sql_query = """SELECT module.name, symbol.section, base.addr + rva, symbol.name 
          FROM volatility.process AS process
            INNER JOIN volatility.base AS base ON process.id = base.process_id
            INNER JOIN module ON module.id = base.module_id
            INNER JOIN mod_pdb ON module.id = mod_pdb.module_id
            INNER JOIN pdb ON pdb.id = mod_pdb.pdb_id
            INNER JOIN symbol ON pdb.id = symbol.pdb_id
          WHERE eproc = ?
          ORDER BY base.addr + rva ASC
        """
      else:
        sql_query = """SELECT module.name, export.ordinal, base.addr + rva, export.name
          FROM volatility.process AS process
            INNER JOIN volatility.base AS base ON process.id = base.process_id
            INNER JOIN module ON module.id = base.module_id
            INNER JOIN export ON module.id = export.module_id
          WHERE eproc = ?
          ORDER BY base.addr + rva ASC
        """

      for module, section_or_ordinal, sym_addr, raw_sym_name in db.execute(sql_query, (eproc_addr,)):
        sym_name = parser.undecorate(raw_sym_name)[0]
        if sym_name == "?":
          sym_name = raw_sym_name
        if self.use_symbols:
          section = section_or_ordinal
        else:
          section = "????"
          if sym_name == "":
            sym_name = str(section_or_ordinal)
        self.table_row(outfd, pid, module, section, "{0:#010x}".format(sym_addr), sym_name)
