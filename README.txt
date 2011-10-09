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


The code for the following plugins was originally written for Challenge 3 of 
the Honeynet Forensic Challenge 2010 (Banking Troubles - see the v1.3 branch 
and http://honeynet.org/challenges/2010_3_banking_troubles for more 
information).

To install these plugins simply include them (e.g. with the --plugins command 
line option), when running Volatility 2.0.

  exportfile.py - this plugin implements the exporting and saving of 
                  _FILE_OBJECT's

For documentation on using these plugins, please use the Volatility 2.0 --help 
option to the plugin command.

CURRENT LIMITATIONS
===================

Under Windows, file's will be loaded into memory as:
  -memory mapped files (and so one needs to access contents via section objects
   etc.)
  -or, shared access files (and so one accesses the file via its shared cache 
   map).
The exportfile plugin will currently only extract files stored in the shared 
cache map.

There is also an unpatched bug in the Volatility 2.0 filescan plugin (version 
1116). This bug causes _FILE_OBJECT addresses to need an extra magic value of 
#18 bytes adding to them!

These limitations will change in the very near future.
