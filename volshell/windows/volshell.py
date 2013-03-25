# Volatility
# Copyright (C) 2008 Volatile Systems
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

import volatility.win32.tasks as win32
import volatility.plugins.volshell as volshell

class WinVolshell(volshell.BaseVolshell):
  """Shell in the (Windows) memory image"""

  def getPidList(self):
    return win32.pslist(self.addrspace)

  def getPid(self, proc):
    return proc.UniqueProcessId

  def getPPid(self, proc):
    return proc.InheritedFromUniqueProcessId.v()

  def getImageName(self, proc):
    return proc.ImageFileName

  def getDTB(self, proc):
    return proc.Pcb.DirectoryTableBase

  def ps(self, render=True, table_data=False, pid=None):
    """Print a process listing.

    Prints a process listing with PID, PPID, image name, and offset.
    """
    if pid:
      if type(pid).__name__ == 'int':
        pid = str(pid)
      if type(pid).__name__ == 'list':
        if len(pid) == 0:
          pid = None
        else:
          pid = ",".join([ str(p) for p in pid ])
    return self.pslist(render=render, table_data=table_data, pid=pid)

  def list_entry(self, head, objname, offset = -1, fieldname = None, forward = True):
    """Traverse a _LIST_ENTRY.

    Traverses a _LIST_ENTRY starting at virtual address head made up of
    objects of type objname. The value of offset should be set to the
    offset of the _LIST_ENTRY within the desired object.
    """
    vm = self.proc.get_process_address_space()
    seen = set()

    if fieldname:
      offset = vm.profile.get_obj_offset(objname, fieldname)

    lst = obj.Object("_LIST_ENTRY", head, vm)
    seen.add(lst)
    if not lst.is_valid():
      return
    while True:
      if forward:
        lst = lst.Flink
      else:
        lst = lst.Blink

      if not lst.is_valid():
        return

      if lst in seen:
        break
      else:
        seen.add(lst)

      nobj = obj.Object(objname, lst.obj_offset - offset, vm)
      yield nobj
