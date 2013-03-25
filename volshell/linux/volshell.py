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

import volatility.plugins.linux.pslist as pslist
import volatility.plugins.volshell as volshell

class LinuxVolshell(volshell.BaseVolshell):
  """Shell in the (Linux) memory image"""

  @staticmethod
  def is_valid_profile(profile):
    return profile.metadata.get('os', 'Unknown').lower() == 'linux'

  def getPidList(self):
    return pslist.linux_pslist(self._config).calculate()

  def getPid(self, proc):
    return proc.pid

  def getPPid(self, proc):
    return "FIXME"

  def getImageName(self, proc):
    return proc.comm

  def getDTB(self, proc):
    return self.addrspace.vtop(proc.mm.pgd) or proc.mm.pgd

  def ps(self, render=True, pid=None, **kwargs):
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
    return self.linux_pslist(render=render, pid=pid, **kwargs)
