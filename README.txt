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

VOLATILITY PLUGINS
==================

Honeynet Plugins
================

The code for the following plugins were originally written for Challenge 3 of 
the Honeynet Forensic Challenge 2010 (Banking Troubles - see https://github.com/carlpulley/volatility/tree/v1.3 
and http://honeynet.org/challenges/2010_3_banking_troubles for more 
information).

  exportfile.py [DEPRECIATED: replaced by dumpfiles in 2.3] - this plugin 
                  implements the exporting and saving of _FILE_OBJECT's. In 
                  addition, file reconstruction functionality is offered by 
                  the plugin.
  exportstack.py - this plugin displays information regarding an _EPROCESS'es 
                  thread data structures.

To install these plugins simply include them (e.g. with the --plugins command 
line option), when running Volatility.

For documentation on using these plugins, please use the Volatility --help 
option to the plugin command.

CURRENT LIMITATIONS: exportfile.py should work with Volatility 2.0 whilst 
  exportstack.py should work with Volatility 2.0, 2.1, 2.2 and 2.3. 

  The exportstack.py plugin currently generates output that is erroneous (see 
  https://github.com/carlpulley/volatility/issues/10).

  These limitations will change in the very near future.


PLUGIN SIMILARITIES: The exportstack.py plugin has a number of similarities to:
  http://code.google.com/p/volatility/wiki/CommandReference#threads
  exportstack.py differs mainly in the fact that it attempts to perform (user and 
  kernel) stack unwinds, whilst threads does not currently do this. In addition, 
  threads currently displays a number of useful _ETHREAD members that 
  exportstack.py does not and incorporates an excellent tag based filtering system.

Other Plugins
=============

  volshell.py - this plugin is a reworking of the existing Volatility volshell
    plugin. Major changes are as follows:
      + hh has been deleted. All help information is now available as Python
        documentation strings. For example, help(self) and dir(self) give general
        command help, whilst help(<command>) provides help on a specific command.
        TODO: when using the IPython command line prompt, __builtin__.help currently 
          overwrites the defined help alias (to self.help), so it is necessary to 
          manually correct this by entering 'help = self.help' after the IPython 
          shell starts. Failing to do this means that individual plugin help will
          be limited.
      + the type of volshell instance launched (i.e. WinVolshell, LinuxVolshell, 
        MacVolshell, etc.) is chosen using the profile metadata (specifically the 
        os attribute). When the OS is unknown, a base Volshell is launched - so 
        just load the image and go!
      + all Volatility plugins are potentially available as commands. These are 
        filtered using the image's profile. Any plugin without a render_text is 
        additionally filtered out. Plugin commands can produce three types of 
        output:
          * with render=True, the plugin prints to stdout
          * with render=False and table_data=True, the plugin hooks the table_header 
            and table_row methods and returns a list of hashes representing the 
            displayed tabular data
          * with render=False and table_data=False, the plugin returns the plugin's 
            calculate result.
        Plugin arguments are scraped by hooking the singleton class conf.ConfObject 
        and grabbing command line options. These are used (after filtering out generic 
        options from commands.Command) to generate valid keyword arguments with 
        defaults (if specified). Plugin commands are dynamically added to the Volshell 
        class and are accessed via self.<command>. For convenience, aliases are 
        generated using '<command> = self.<command>'.
      + it is now possible to override exiting commands in BaseVolshell (e.g. see ps 
        in WinVolshell, LinuxVolshell and MacVolshell) and to add in commands that 
        are OS specific (e.g. see WinVolshell for list_entry).
      + a source command has been added to ease loading Volshell scripts into the 
        current session. Any function in the loaded file matching the pattern:

          def func(self, ..):
            ..

        is blindly bound to the current Volshell instance and made available as self.func(..) 
        or func(self, ..). If this code was located in /path/to/func.py then it can be sourced
        using the Volshell command (for convenience, sys.path is also searched):

          source("/path/to/func.py")

        TODO: implement code to assign 'func = self.func' in the Volshell session.
      + [EXPERIMENTAL] it is possible to use the Volshell plugin in a Volatility as a library 
        like manner [1]. The following simple code demonstrates the idea by printing out a 
        (sorted) process tree:

          from volatility.plugins.volshell import Volshell
          from itertools import groupby

          def analyse(mem_image):
            shell = Volshell(filename=mem_image)
            data = groupby(sorted(shell.pslist(), key=lambda x: x['PPID']), lambda x: x['PPID'])
            for ppid, pids in data:
              print "PPID: {0}".format(ppid)
              for pid in pids:
                print "  PID: {0}".format(pid['PID'])

        In library mode, the Volshell plugin related methods (i.e. the help, calculate  
        and render_* methods) are disabled.
        TODO: generate examples demonstrating the potential uses for Volshell script 
          and library code.
      + [EXPERIMENTAL] based on [2] and [3], there appears to be a longer term preference 
        for IPython being the default command line experience (+1 from myself!). So, when 
        we failover to a basic Python Volshell, an IPython "nag" banner is displayed on 
        startup.

    INSTALLATION: run the following commands to install (WARNING: the existing Volshell 
      code is deleted):

        rm $VOLATILITY_SRC/volatility/plugins/linux/linux_volshell.py
        rm $VOLATILITY_SRC/volatility/plugins/mac/mac_volshell.py
        cp -f volshell/volshell.py $VOLATILITY_SRC/volatility/plugins/
        cp -fr volshell/linux $VOLATILITY_SRC/volatility/plugins/
        cp -fr volshell/mac $VOLATILITY_SRC/volatility/plugins/
        cp -fr volshell/windows $VOLATILITY_SRC/volatility/plugins/

REFERENCES:
===========

[1] Using Volatility as a Library (accessed 24/Mar/2013):
      https://code.google.com/p/volatility/wiki/VolatilityUsage23#Using_Volatility_as_a_Library
[2] Volatility Roadmap: Volatility 3.0 (Official Tech Preview Merge) (accessed 24/Mar/2013):
      https://code.google.com/p/volatility/wiki/VolatilityRoadmap#Volatility_3.0_(Official_Tech_Preview_Merge)
[3] Volatility Technology Preview Documentation: Tutorial (accessed 24/Mar/2013):
      https://volatility.googlecode.com/svn/branches/scudette/docs/tutorial.html
