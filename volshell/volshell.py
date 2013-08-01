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

"""
@author:       AAron Walters, Brendan Dolan-Gavitt and Carl Pulley
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com, bdolangavitt@wesleyan.edu, c.j.pulley@hud.ac.uk
@organization: Volatile Systems
"""

from inspect import currentframe, getargspec, isfunction, ismethod
import os
import pydoc
import struct
import sys
import volatility.addrspace as addrspace
import volatility.commands as commands
import volatility.conf as conf
import volatility.debug as debug
import volatility.exceptions as exceptions
import volatility.obj as obj
import volatility.plugins as plugins
import volatility.registry as registry
import volatility.utils as utils

try:
    import distorm3 #pylint: disable-msg=F0401
except ImportError:
    pass

class VolshellException(exceptions.VolatilityException):
  """General exception for handling errors whilst processing shell commands"""
  pass

class Config(conf.ConfObject):
  def __init__(self):
    conf.ConfObject.__init__(self)
    self.option_hook = {}

  def add_option(self, option, **args):
    option = option.lower().replace("-", "_")
    self.option_hook[option] = { 'default': str(args['default']) if 'default' in args else "", 'help': args['help'] if 'help' in args else "", 'type': args['type'] if 'type' in args else '' }
    if 'type' in args and args['type'] == 'choice':
      self.option_hook[option]['choices'] = args['choices'] if 'choices' in args else []

class Plugin(object):
  def __init__(self, shell, module_name, module_class):
    if "render_text" not in dir(module_class):
      raise VolshellException("{0} does not support render_text".format(module_name))
    if module_name in dir(shell):
      raise VolshellException("{0} is already registered".format(module_name))
		
    self.module = module_class
    self.base_config = shell.base_config
    
    # Setup plugin instance documentation string
    config = Config()
    self.module(config)
    args = [ arg for arg in config.option_hook if arg not in self.base_config ]
    arg_help = [ 
      "render[=False] (bool): determines if output is printed or a data structure is returned", 
      "table_data[=True] (bool): determines if returned data should be from table_header/table_row hooking or from the  output of {0}.calculate()".format(self.module.__name__) 
    ] + [ 
      "{0}{1}{2}: {3}".format(opt, "[={0}]".format(config.option_hook[opt]['default']) if config.option_hook[opt]['default']   != "" else "", 
      " ({0})".format(config.option_hook[opt]['type']) if config.option_hook[opt]['type'] != "" else "", 
      config.option_hook[opt]['help']) for opt in sorted(args) 
    ]
    self.__name__ = module_name
    self.__doc__ = "{0}\n\nArguments:\n  {1}\n".format(pydoc.getdoc(self.module), "\n  ".join(arg_help))

  def __call__(self, *args, **kwargs):
    if "render" not in kwargs:
      kwargs["render"] = False
    if "table_data" not in kwargs:
      kwargs["table_data"] = True

    config = Config()
    self.module(config)
    default_config = config.option_hook
    plugin_options = default_config.keys() + ["render", "table_data"]

    config_arg = conf.ConfObject()
    for key in kwargs:
      if key not in plugin_options:
        raise VolshellException("{0} is not a valid keyword argument".format(key))
      if key in self.base_config:
        raise VolshellException("{0} is not usable within volshell".format(key))
      config_arg.update(key, kwargs[key])

    module_class = self.module
    class HookTable(module_class):
      def __init__(self, config, *_args, **_kwargs):
        self.table_title = None
        self.table_data = []
        module_class.__init__(self, config, *_args, **_kwargs)
      
      def format_value(self, value, fmt):
        return value

      def table_header(self, outfd, title_format_list = None):
        self.table_title = [ title for title, spec in title_format_list ]
        module_class.table_header(self, outfd, title_format_list)
  
      def table_row(self, outfd, *args):
        if self.table_title == None:
          raise VolshellException("no table header has been set and the plugin is adding rows!")
        row = dict(zip(self.table_title, args))
        self.table_data += [row]
        module_class.table_row(self, outfd, *args)

    module = HookTable(config_arg)
    data = module.calculate()
    if "render" in kwargs and kwargs["render"]:
      module.render_text(sys.stdout, data)
      result = None
    elif "table_data" in kwargs and kwargs["table_data"]:
      with open(os.devnull, 'w') as null:
        module.render_text(null, data)
      result = module.table_data
    else:
      result = data
    # conf.ConfObject is a singleton, so first we remove any config 
    # options we may have set
    for key in plugin_options:
      try:
        config_arg.remove_option(key)
      except ValueError:
        pass
    return result


class BaseVolshell(commands.Command):
  def __init__(self, config):
    commands.Command.__init__(self, config)

    config.add_option('OFFSET', short_option = 'o', default = None,
                      help = 'EPROCESS Offset (in hex) in kernel address space',
                      action = 'store', type = 'int')
    config.add_option('IMNAME', short_option = 'n', default = None,
                      help = 'Process executable image name',
                      action = 'store', type = 'str')
    config.add_option('PID', short_option = 'p', default = None,
                      help = 'Operate on these Process IDs (comma-separated)',
                      action = 'store', type = 'str')

    self.addrspace = utils.load_as(config)

    hooked_config = Config()
    commands.Command(hooked_config)
    self.base_config = hooked_config.option_hook

    # Add shell plugins to object instance
    self.shell_plugins = set()
    plugins = registry.get_plugin_classes(commands.Command, lower = True)
    # Filter plugins to those that are valid for the current profile (and remove the .*volshell plugins!)
    cmds = dict((cmd, plugin) for cmd, plugin in plugins.items() if plugin.is_valid_profile(self.addrspace.profile) and not cmd.endswith("volshell"))
    for module in cmds.keys():
      try:
        plugin = Plugin(self, module, cmds[module])
        setattr(self.__class__, module, plugin)
        self.shell_plugins.add(module)
      except VolshellException, exn:
        print "WARNING: {0} not loaded as a volshell command ({1})".format(module, exn)

    self.proc = None

  def cc(self, offset = None, pid = None, name = None):
    """Change current shell context.

    This function changes the current shell context to to the process
    specified. The process specification can be given as a virtual address
    (option: offset), PID (option: pid), or process name (option: name).

    If multiple processes match the given PID or name, you will be shown a
    list of matching processes, and will have to specify by offset.

    Calling this function with no arguments simply prints out the current 
    context.
    """
    if pid is not None:
      offsets = []
      for p in self.getPidList():
        if self.getPid(p).v() == pid:
          offsets.append(p)
      if not offsets:
        raise VolshellException("Unable to find process matching pid {0}".format(pid))
      elif len(offsets) > 1:
        err = "Multiple processes match {0}, please specify by offset\n".format(pid)
        err += "Matching process offsets: {0}".format("; ".join([ "{0:#08X}".format(off.v()) for off in offsets ]))
        raise VolshellException(err)
      else:
        offset = offsets[0].v()
    elif name is not None:
      offsets = []
      for p in self.getPidList():
        if self.getImageName(p).find(name) >= 0:
          offsets.append(p)
      if not offsets:
        raise VolshellException("Unable to find process matching name {0}".format(name))
      elif len(offsets) > 1:
        err = "Multiple processes match name {0}, please specify by PID or offset\n".format(name)
        err += "Matching process offsets: {0}".format("; ".join([ "{0:#08X}".format(off.v()) for off in offsets ]))
        raise VolshellException(err)
      else:
        offset = offsets[0].v()

    if pid is not None or name is not None or offset is not None:
      self.proc = obj.Object("_EPROCESS", offset = offset, vm = self.addrspace)

    print "Current context: process {0}, pid={1}, ppid={2}, DTB={3:#x}".format(self.getImageName(self.proc), self.getPid(self.proc).v(), self.getPPid(self.proc), self.getDTB(self.proc).v())

  def db(self, address, length = 0x80, space = None):
    """Print bytes as canonical hexdump.
    
    This function prints bytes at the given virtual address as a canonical
    hexdump. The address will be translated in the current process context
    (see help on cc for information on how to change contexts).
    
    The length parameter (default: 0x80) specifies how many bytes to print,
    the width parameter (default: 16) allows you to change how many bytes per
    line should be displayed, and the space parameter allows you to
    optionally specify the address space to read the data from.
    """
    if space is None:
      space = self.proc.get_process_address_space()
    data = space.read(address, length)
    if data is None:
      raise VolshellException("Memory unreadable at {0:#08x}".format(address))

    for offset, hexchars, chars in utils.Hexdump(data):
      print "{0:#010x}  {1:<48}  {2}".format(address + offset, hexchars, ''.join(chars))

  def dd(self, address, length = 0x80, space = None):
    """Print dwords at address.

    This function prints the data at the given address, interpreted as
    a series of dwords (unsigned four-byte integers) in hexadecimal.
    The address will be translated in the current process context
    (see help on cc for information on how to change contexts).
    
    The optional length parameter (default: 0x80) controls how many bytes
    to display, and space allows you to optionally specify the address space
    to read the data from.
    """
    if space is None:
      space = self.proc.get_process_address_space()
    # round up to multiple of 4
    if length % 4 != 0:
      length = (length + 4) - (length % 4)
    data = space.read(address, length)
    if data is None:
      raise VolshellException("Memory unreadable at {0:#08x}".format(address))
    dwords = []
    for i in range(0, length, 4):
      (dw,) = struct.unpack("<L", data[i:i + 4])
      dwords.append(dw)

    if len(dwords) % 4 == 0: 
      lines = len(dwords) / 4
    else: 
      lines = len(dwords) / 4 + 1

    for i in range(lines):
      ad = address + i * 0x10
      lwords = dwords[i * 4:i * 4 + 4]
      print ("{0:08x}  ".format(ad)) + " ".join("{0:08x}".format(l) for l in lwords)

  def dq(self, address, length = 0x80, space = None):
    """Print qwords at address.

    This function prints the data at the given address, interpreted as
    a series of qwords (unsigned eight-byte integers) in hexadecimal.
    The address will be translated in the current process context
    (see help on cc for information on how to change contexts).
    
    The optional length parameter (default: 0x80) controls how many bytes
    to display, and space allows you to optionally specify the address space
    to read the data from.
    """
    if space is None:
      space = self.proc.get_process_address_space()

    # round up 
    if length % 8 != 0:
      length = (length + 8) - (length % 8)

    qwords = obj.Object("Array", targetType = "unsigned long long",
      offset = address, count = length / 8, vm = space)

    if qwords is None:
      raise VolshellException("Memory unreadable at {0:#08x}".format(address))

    for qword in qwords:
      print "{0:#x} {1:#x}".format(qword.obj_offset, qword.v())

  def dt(self, objct, address = None, space = None):
    """Describe an object or show type info.

    Show the names and values of a complex object (struct). If the name of a
    structure is passed, show the struct's members and their types.

    You can also pass a type name and an address in order to on-the-fly
    interpret a given address as an instance of a particular structure.

    Examples:
        # Dump the current process object
        dt(self.proc)
        # Show the _EPROCESS structure
        dt('_EPROCESS')
        # Overlay an _EPROCESS structure at 0x81234567
        dt('_EPROCESS', 0x81234567)
    """
    profile = (space or self.proc.obj_vm).profile

    if address is not None:
      objct = obj.Object(objct, address, space or self.proc.get_process_address_space())

    if isinstance(objct, str):
      size = profile.get_obj_size(objct)
      membs = [ (profile.get_obj_offset(objct, m), m, profile.vtypes[objct][1][m][1]) for m in profile.vtypes[objct][1] ]
      print repr(objct), "({0} bytes)".format(size)
      for o, m, t in sorted(membs):
        print "{0:6}: {1:30} {2}".format(hex(o), m, t)
    elif isinstance(objct, obj.BaseObject):
      membs = [ (o, m) for m, (o, _c) in objct.members.items() ]
      print repr(objct)
      offsets = []
      for o, m in sorted(membs):
        val = getattr(objct, m)
        if isinstance(val, list):
          val = [ str(v) for v in val ]

        # Handle a potentially callable offset
        if callable(o):
          o = o(objct) - objct.obj_offset

        offsets.append((o, m, val))

      # Deal with potentially out of order offsets
      offsets.sort(key = lambda x: x[0])

      for o, m, val in offsets:
        print "{0:6}: {1:30} {2}".format(hex(o), m, val)
    elif isinstance(objct, obj.NoneObject):
      raise VolshellException("could not instantiate object\n\nReason: {0}".format(objct.reason))
    else:
      raise VolshellException("first argument not an object or known type\n\nUsage:\n{0}\n".format(self.dt.__doc__))

  def dis(self, address, length = 128, space = None, mode = None):
    """Disassemble code at a given address.

    Disassembles code starting at address for a number of bytes
    given by the length parameter (default: 128).

    Note: This feature requires distorm, available at
        http://www.ragestorm.net/distorm/

    The mode is '32bit' or '64bit'. If not supplied, the disasm
    mode is taken from the profile. 
    """
    if not sys.modules.has_key("distorm3"):
      raise VolshellException("Disassembly unavailable, distorm not installed (see http://code.google.com/p/distorm/ for further information)")
    if space is None:
      space = self.proc.get_process_address_space()

    if mode is None:
      mode = space.profile.metadata.get('memory_model', '32bit')

    if mode == '32bit':
      distorm_mode = distorm3.Decode32Bits
    else:
      distorm_mode = distorm3.Decode64Bits

    data = space.read(address, length)
    iterable = distorm3.DecodeGenerator(address, data, distorm_mode)
    for (offset, _size, instruction, hexdump) in iterable:
      print "{0:<#8x} {1:<32} {2}".format(offset, hexdump, instruction)

  def source(self, script):
    """Source a python file (i.e. script) into the current volshell session.

    All loaded functions matching:
      def cmd(self, ..):
        ..
    are bound as methods to the current volshell session (i.e. self).

    Paths in sys.path (and so PYTHONPATH) are searched to locate the 
    script file.
    
    TODO: no shell alias to the sourced method is created.
    """
    from imp import load_source
    try:
      script_path = None
      for base_path in [''] + sys.path:
        if os.path.exists(base_path + os.sep + script):
          script_path = base_path + os.sep + script
          break
      if script_path is None:
        raise VolshellException("failed to load {0} (no such file)".format(script))
      cmd = load_source('volatility.plugins.volshell', script_path)
      loaded = 0
      for func in dir(cmd):
        if not func.startswith("__") and isfunction(cmd.__getattribute__(func)) and len(getargspec(cmd.__getattribute__(func))) > 0 and getargspec(cmd.__getattribute__(func)).args[0] == 'self':
          setattr(self.__class__, func, cmd.__getattribute__(func))
          loaded +=1
          print "{0} successfully loaded".format(func)
      if loaded > 0:
        print "Finished processing {0} ({1} commands loaded)".format(script, loaded)
      else:
        raise VolshellException("no commands loaded")
    except IOError, exn:
      raise VolshellException("failed to load {0} ({1})".format(script, exn))
    except SyntaxError, exn:
      raise VolshellException("failed to load {0} ({1})".format(script, exn))

  # TODO: catch and print out VolshellException's
  def render_text(self, _outfd, _data):
    # With Plugin object instances, dynamically setup the Plugin class doc strings (as there's
    # only one __doc__ per object/class function)
    class VolshellHelper(object):
      """Define the builtin 'help'.

      This is a wrapper around pydoc.help (with a twist of lemon).
      """
      def __repr__(self):
        return "To get help, type 'help(self)', 'dir(self)' or 'help(<command>)"

      def __call__(self, obj=None):
        if isinstance(obj, Plugin):
          obj.__call__.__func__.__doc__ = obj.__doc__
        return pydoc.help(obj or self)

    self.help = VolshellHelper() # Ensure the Volshell help function is defined
    help = self.help

    # Build alises for shell functions and plugins
    for nm in self.shell_plugins:
      exec "{0} = self.{0}".format(nm) in globals(), locals()
    for nm in dir(self):
      if nm not in dir(commands.Command) and ismethod(self.__getattribute__(nm)):
        exec "{0} = self.{0}".format(nm) in globals(), locals()

    # Break into shell
    print "Welcome to Volshell!"
    print
    print "Metadata:"
    print "  Image: {0}  ({1} bytes [{2}])".format(self._config.LOCATION, self.addrspace.base.fsize, self.addrspace.base.mode.upper())
    print "  Address Space: {0} ({1})".format(type(self.addrspace).__name__, type(self.addrspace.base).__name__)
    print "  Profile: {0}".format(type(self.addrspace.profile).__name__)
    print "  OS: {0} ({1} {2})".format(self.addrspace.profile.metadata.get("os", "UNKOWN"), self.addrspace.profile.metadata.get("arch", "x86"), self.addrspace.profile.metadata.get("memory_model", "32bit"))
    print
    print help
    print

    if self._config.OFFSET is not None:
      cc(offset = self._config.OFFSET)
    elif self._config.PID is not None:
      cc(pid = self._config.PID)
    elif self._config.IMNAME is not None:
      cc(name = self._config.IMNAME)
    else:
      # Just use the first process, whatever it is
      for p in self.getPidList():
        cc(offset = p.v())
        break

    try:
      from IPython.frontend.terminal.embed import InteractiveShellEmbed #pylint: disable-msg=W0611,F0401
      shell = InteractiveShellEmbed(banner1 = "TODO: manually enter 'help = self.help' to enable full help functionality")
      shell()
    except ImportError, exn:
      import code

      frame = currentframe()

      # Try to enable tab completion
      try:
        import rlcompleter, readline #pylint: disable-msg=W0612
        readline.parse_and_bind("tab: complete")
      except ImportError:
        pass

      # evaluate commands in current namespace
      namespace = frame.f_globals.copy()
      namespace.update(frame.f_locals)

      code.interact(banner = "Note: for an enhanced command line experience, upgrade to IPython (see http://ipython.org)", local = namespace)

class Volshell(BaseVolshell):
  """Shell in the memory image (supports *arbitrary* images).

  In the current shell session: 
    self.proc has the current context's _EPROCESS object; 
    the images Kernel/Virtual address space is in self.addrspace (use self.proc.get_process_address_space() for Process address space); 
    and all shell command are self.<command> methods (aliased using <command> = self.<command>).

  Creating an instance of Volshell *without* specifying a config object causes Volshell to 
  operate in library mode. So, the Volshell help, calculate and render_* functions are all 
  disabled.
  """

  def __init__(self, config=None, **kwargs):
    # If no config is argument present, we are in library mode - so build a config object using the kwargs dict
    if config is None:
      self.library_mode = True
      self.__init__.__func__.__doc__ = "INITIALISED IN LIBRARY MODE"
      # Use kwargs to fake command line arguments
      if "plugins" in kwargs:
        plugins.__path__ += kwargs["plugins"].split(plugins.plugin_separator)
      if "debug" in kwargs:
        debug.setup(min(int(kwargs["debug"]), debug.MAX_DEBUG))
      else:
        debug.setup()
      sys.argv = ["volshell"] + [ "--{0}={1}".format(key, val) for key, val in kwargs.items() if key not in ["plugins", "debug"] ]
      # (Singleton) config object is basically empty (this is the first time it is created)
      config = conf.ConfObject()
      # Load up plugin modules now (they may set config options)
      registry.PluginImporter()
      registry.register_global_options(config, addrspace.BaseAddressSpace)
      registry.register_global_options(config, commands.Command)
      # Finish setting up the conf.ConfObject() singleton
      config.parse_options(False)
      BaseVolshell.__init__(self, config)
      if not config.LOCATION:
        raise VolshellException("please specify a location or filename keyword")
      # Disable Volshell help, calculate and render_* methods
      def disable_method(self, *args, **kwargs):
        """LIBRARY MODE: METHOD DISABLED"""
        raise VolshellException("LIBRARY MODE: METHOD DISABLED")
      for method in dir(self):
        if (method in ["help", "calculate"] or method.startswith("render_")) and ismethod(self.__getattribute__(method)):
          setattr(self.__class__, method, disable_method)
    else:
      self.library_mode = False
      self.__init__.__func__.__doc__ = "INITIALISED IN PLUGIN/SHELL MODE"
      BaseVolshell.__init__(self, config)

    image_os = self.addrspace.profile.metadata.get("os", "UNKNOWN")
    if image_os == "windows":
      from volatility.plugins.windows.volshell import WinVolshell
      Volshell.__bases__ = (WinVolshell,)
    elif image_os == "linux":
      from volatility.plugins.linux.volshell import LinuxVolshell
      Volshell.__bases__ = (LinuxVolshell,)
    elif image_os == "mac":
      from volatility.plugins.mac.volshell import MacVolshell
      Volshell.__bases__ = (MacVolshell,)
    else:
      print "WARNING: {0} is an unknown or unsupported OS - using a base Volshell".format(image_os)
