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
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      brendandg@gatech.edu
@organization: Georgia Institute of Technology
"""

from forensics.object2 import *
from forensics.win32.tasks import process_list
from forensics.win32.lists import list_entry
from forensics.object import get_obj_offset
from vutils import *
from datetime import timedelta

# Types we'll need
gdi_types = {
  '_W32THREAD' : [ 0x28, {
    'MsgQueue' : [0xD0, ['_MSG_QUEUE']],
} ],
  '_MSG_QUEUE' : [ 0xC, {
    'Head' : [ 0x0, ['pointer', ['_MSG_QUEUE_ENTRY']]],
    'Tail' : [ 0x4, ['pointer', ['_MSG_QUEUE_ENTRY']]],
    'Count' : [ 0x8, ['unsigned long']],
} ],
  '_MSG_QUEUE_ENTRY' : [ 0x2c, {
    'pNext' : [ 0x0, ['pointer', ['_MSG_QUEUE_ENTRY']]],
    'pPrev' : [ 0x4, ['pointer', ['_MSG_QUEUE_ENTRY']]],
    'Msg' : [ 0x8, ['_MSG']],
} ],
  '_MSG' : [ 0x24, {
    'hWnd' : [ 0x0, ['unsigned long']],
    'ulMsg' : [ 0x4, ['unsigned long']],
    'wParam' : [ 0x8, ['unsigned long']],
    'lParam' : [ 0xc, ['unsigned long']],
    'time' : [ 0x10, ['unsigned long']],
    'pt' : [ 0x14, ['_POINT']], # Mouse cursor position
    'dwUnknown' : [ 0x1c, ['unsigned long']],
    'dwExtraInfo' : [ 0x20, ['unsigned long']],
} ],
  '_POINT' : [ 0x8, {
    'x' : [ 0x0, ['long']],
    'y' : [ 0x4, ['long']],
} ],
}

# Helper function. Must be located here because it gets used immediately
def symm(d):
    """Make a dictionary symmetric"""
    d.update((v,k) for k,v in d.items())

# Window message constants
WM_CONSTS = {
    'WM_NULL' : 0x0000,
    'WM_CREATE' : 0x0001,
    'WM_DESTROY' : 0x0002,
    'WM_MOVE' : 0x0003,
    'WM_SIZEWAIT' : 0x0004,
    'WM_SIZE' : 0x0005,
    'WM_ACTIVATE' : 0x0006,
    'WM_SETFOCUS' : 0x0007,
    'WM_KILLFOCUS' : 0x0008,
    'WM_SETVISIBLE' : 0x0009,
    'WM_ENABLE' : 0x000a,
    'WM_SETREDRAW' : 0x000b,
    'WM_SETTEXT' : 0x000c,
    'WM_GETTEXT' : 0x000d,
    'WM_GETTEXTLENGTH' : 0x000e,
    'WM_PAINT' : 0x000f,
    'WM_CLOSE' : 0x0010,
    'WM_QUERYENDSESSION' : 0x0011,
    'WM_QUIT' : 0x0012,
    'WM_QUERYOPEN' : 0x0013,
    'WM_ERASEBKGND' : 0x0014,
    'WM_SYSCOLORCHANGE' : 0x0015,
    'WM_ENDSESSION' : 0x0016,
    'WM_SYSTEMERROR' : 0x0017,
    'WM_SHOWWINDOW' : 0x0018,
    'WM_CTLCOLOR' : 0x0019,
    'WM_SETTINGCHANGE' : 0x001a,
    'WM_DEVMODECHANGE' : 0x001b,
    'WM_ACTIVATEAPP' : 0x001c,
    'WM_FONTCHANGE' : 0x001d,
    'WM_TIMECHANGE' : 0x001e,
    'WM_CANCELMODE' : 0x001f,
    'WM_SETCURSOR' : 0x0020,
    'WM_MOUSEACTIVATE' : 0x0021,
    'WM_CHILDACTIVATE' : 0x0022,
    'WM_QUEUESYNC' : 0x0023,
    'WM_GETMINMAXINFO' : 0x0024,
    'WM_PAINTICON' : 0x0026,
    'WM_ICONERASEBKGND' : 0x0027,
    'WM_NEXTDLGCTL' : 0x0028,
    'WM_ALTTABACTIVE' : 0x0029,
    'WM_SPOOLERSTATUS' : 0x002a,
    'WM_DRAWITEM' : 0x002b,
    'WM_MEASUREITEM' : 0x002c,
    'WM_DELETEITEM' : 0x002d,
    'WM_VKEYTOITEM' : 0x002e,
    'WM_CHARTOITEM' : 0x002f,
    'WM_SETFONT' : 0x0030,
    'WM_GETFONT' : 0x0031,
    'WM_SETHOTKEY' : 0x0032,
    'WM_GETHOTKEY' : 0x0033,
    'WM_FILESYSCHANGE' : 0x0034,
    'WM_ISACTIVEICON' : 0x0035,
    'WM_QUERYPARKICON' : 0x0036,
    'WM_QUERYDRAGICON' : 0x0037,
    'WM_QUERYSAVESTATE' : 0x0038,
    'WM_COMPAREITEM' : 0x0039,
    'WM_TESTING' : 0x003a,
    'WM_GETOBJECT' : 0x003d,
    'WM_ACTIVATESHELLWINDOW' : 0x003e,
    'WM_COMPACTING' : 0x0041,
    'WM_COMMNOTIFY' : 0x0044,
    'WM_WINDOWPOSCHANGING' : 0x0046,
    'WM_WINDOWPOSCHANGED' : 0x0047,
    'WM_POWER' : 0x0048,
    'WM_COPYDATA' : 0x004a,
    'WM_CANCELJOURNAL' : 0x004b,
    'WM_KEYF1' : 0x004d,
    'WM_NOTIFY' : 0x004e,
    'WM_INPUTLANGCHANGEREQUEST' : 0x0050,
    'WM_INPUTLANGCHANGE' : 0x0051,
    'WM_TCARD' : 0x0052,
    'WM_HELP' : 0x0053,
    'WM_USERCHANGED' : 0x0054,
    'WM_NOTIFYFORMAT' : 0x0055,
    'WM_CONTEXTMENU' : 0x007b,
    'WM_STYLECHANGING' : 0x007c,
    'WM_STYLECHANGED' : 0x007d,
    'WM_DISPLAYCHANGE' : 0x007e,
    'WM_GETICON' : 0x007f,
    'WM_SETICON' : 0x0080,
    'WM_NCCREATE' : 0x0081,
    'WM_NCDESTROY' : 0x0082,
    'WM_NCCALCSIZE' : 0x0083,
    'WM_NCHITTEST' : 0x0084,
    'WM_NCPAINT' : 0x0085,
    'WM_NCACTIVATE' : 0x0086,
    'WM_GETDLGCODE' : 0x0087,
    'WM_SYNCPAINT' : 0x0088,
    'WM_SYNCTASK' : 0x0089,
    'WM_NCMOUSEMOVE' : 0x00a0,
    'WM_NCLBUTTONDOWN' : 0x00a1,
    'WM_NCLBUTTONUP' : 0x00a2,
    'WM_NCLBUTTONDBLCLK' : 0x00a3,
    'WM_NCRBUTTONDOWN' : 0x00a4,
    'WM_NCRBUTTONUP' : 0x00a5,
    'WM_NCRBUTTONDBLCLK' : 0x00a6,
    'WM_NCMBUTTONDOWN' : 0x00a7,
    'WM_NCMBUTTONUP' : 0x00a8,
    'WM_NCMBUTTONDBLCLK' : 0x00a9,
    'WM_NCXBUTTONDOWN' : 0x00ab,
    'WM_NCXBUTTONUP' : 0x00ac,
    'WM_NCXBUTTONDBLCLK' : 0x00ad,
    'WM_INPUT_DEVICE_CHANGE' : 0x00fe,
    'WM_INPUT' : 0x00ff,
    'WM_KEYDOWN' : 0x0100,
    'WM_KEYUP' : 0x0101,
    'WM_CHAR' : 0x0102,
    'WM_DEADCHAR' : 0x0103,
    'WM_SYSKEYDOWN' : 0x0104,
    'WM_SYSKEYUP' : 0x0105,
    'WM_SYSCHAR' : 0x0106,
    'WM_SYSDEADCHAR' : 0x0107,
    'WM_UNICHAR' : 0x0109,
    'WM_IME_STARTCOMPOSITION' : 0x010d,
    'WM_IME_ENDCOMPOSITION' : 0x010e,
    'WM_IME_COMPOSITION' : 0x010f,
    'WM_IME_KEYLAST' : 0x010f,
    'WM_INITDIALOG' : 0x0110,
    'WM_COMMAND' : 0x0111,
    'WM_SYSCOMMAND' : 0x0112,
    'WM_TIMER' : 0x0113,
    'WM_HSCROLL' : 0x0114,
    'WM_VSCROLL' : 0x0115,
    'WM_INITMENU' : 0x0116,
    'WM_INITMENUPOPUP' : 0x0117,
    'WM_MENUSELECT' : 0x011F,
    'WM_MENUCHAR' : 0x0120,
    'WM_ENTERIDLE' : 0x0121,
    'WM_MENURBUTTONUP' : 0x0122,
    'WM_MENUDRAG' : 0x0123,
    'WM_MENUGETOBJECT' : 0x0124,
    'WM_UNINITMENUPOPUP' : 0x0125,
    'WM_MENUCOMMAND' : 0x0126,
    'WM_CHANGEUISTATE' : 0x0127,
    'WM_UPDATEUISTATE' : 0x0128,
    'WM_QUERYUISTATE' : 0x0129,
    'WM_LBTRACKPOINT' : 0x0131,
    'WM_CTLCOLORMSGBOX' : 0x0132,
    'WM_CTLCOLOREDIT' : 0x0133,
    'WM_CTLCOLORLISTBOX' : 0x0134,
    'WM_CTLCOLORBTN' : 0x0135,
    'WM_CTLCOLORDLG' : 0x0136,
    'WM_CTLCOLORSCROLLBAR' : 0x0137,
    'WM_CTLCOLORSTATIC' : 0x0138,
    'MN_GETHMENU' : 0x01E1,
    'WM_MOUSEMOVE' : 0x0200,
    'WM_LBUTTONDOWN' : 0x0201,
    'WM_LBUTTONUP' : 0x0202,
    'WM_LBUTTONDBLCLK' : 0x0203,
    'WM_RBUTTONDOWN' : 0x0204,
    'WM_RBUTTONUP' : 0x0205,
    'WM_RBUTTONDBLCLK' : 0x0206,
    'WM_MBUTTONDOWN' : 0x0207,
    'WM_MBUTTONUP' : 0x0208,
    'WM_MBUTTONDBLCLK' : 0x0209,
    'WM_MOUSEWHEEL' : 0x020A,
    'WM_XBUTTONDOWN' : 0x020B,
    'WM_XBUTTONUP' : 0x020C,
    'WM_XBUTTONDBLCLK' : 0x020D,
    'WM_MOUSEHWHEEL' : 0x020E,
    'WM_MOUSEFIRST' : 0x0200,
    'WM_MOUSELAST' : 0x020E,
    'WM_PARENTNOTIFY' : 0x0210,
    'WM_ENTERMENULOOP' : 0x0211,
    'WM_EXITMENULOOP' : 0x0212,
    'WM_NEXTMENU' : 0x0213,
    'WM_SIZING' : 0x0214,
    'WM_CAPTURECHANGED' : 0x0215,
    'WM_MOVING' : 0x0216,
    'WM_POWERBROADCAST' : 0x0218,
    'WM_DEVICECHANGE' : 0x0219,
    'WM_MDICREATE' : 0x0220,
    'WM_MDIDESTROY' : 0x0221,
    'WM_MDIACTIVATE' : 0x0222,
    'WM_MDIRESTORE' : 0x0223,
    'WM_MDINEXT' : 0x0224,
    'WM_MDIMAXIMIZE' : 0x0225,
    'WM_MDITILE' : 0x0226,
    'WM_MDICASCADE' : 0x0227,
    'WM_MDIICONARRANGE' : 0x0228,
    'WM_MDIGETACTIVE' : 0x0229,
    'WM_MDIREFRESHMENU' : 0x0234,
    'WM_DROPOBJECT' : 0x022A,
    'WM_QUERYDROPOBJECT' : 0x022B,
    'WM_BEGINDRAG' : 0x022C,
    'WM_DRAGLOOP' : 0x022D,
    'WM_DRAGSELECT' : 0x022E,
    'WM_DRAGMOVE' : 0x022F,
    'WM_MDISETMENU' : 0x0230,
    'WM_ENTERSIZEMOVE' : 0x0231,
    'WM_EXITSIZEMOVE' : 0x0232,
    'WM_DROPFILES' : 0x0233,
    'WM_IME_SETCONTEXT' : 0x0281,
    'WM_IME_NOTIFY' : 0x0282,
    'WM_IME_CONTROL' : 0x0283,
    'WM_IME_COMPOSITIONFULL' : 0x0284,
    'WM_IME_SELECT' : 0x0285,
    'WM_IME_CHAR' : 0x0286,
    'WM_IME_REQUEST' : 0x0288,
    'WM_IME_KEYDOWN' : 0x0290,
    'WM_IME_KEYUP' : 0x0291,
    'WM_NCMOUSEHOVER' : 0x02A0,
    'WM_MOUSEHOVER' : 0x02A1,
    'WM_MOUSELEAVE' : 0x02A3,
    'WM_NCMOUSELEAVE' : 0x02A2,
    'WM_WTSSESSION_CHANGE' : 0x02B1,
    'WM_TABLET_FIRST' : 0x02c0,
    'WM_TABLET_LAST' : 0x02df,
    'WM_CUT' : 0x0300,
    'WM_COPY' : 0x0301,
    'WM_PASTE' : 0x0302,
    'WM_CLEAR' : 0x0303,
    'WM_UNDO' : 0x0304,
    'WM_RENDERFORMAT' : 0x0305,
    'WM_RENDERALLFORMATS' : 0x0306,
    'WM_DESTROYCLIPBOARD' : 0x0307,
    'WM_DRAWCLIPBOARD' : 0x0308,
    'WM_PAINTCLIPBOARD' : 0x0309,
    'WM_VSCROLLCLIPBOARD' : 0x030A,
    'WM_SIZECLIPBOARD' : 0x030B,
    'WM_ASKCBFORMATNAME' : 0x030C,
    'WM_CHANGECBCHAIN' : 0x030D,
    'WM_HSCROLLCLIPBOARD' : 0x030E,
    'WM_QUERYNEWPALETTE' : 0x030F,
    'WM_PALETTEISCHANGING' : 0x0310,
    'WM_PALETTECHANGED' : 0x0311,
    'WM_HOTKEY' : 0x0312,
    'WM_PRINT' : 0x0317,
    'WM_PRINTCLIENT' : 0x0318,
    'WM_APPCOMMAND' : 0x0319,
    'WM_THEMECHANGED' : 0x031A,
    'WM_CLIPBOARDUPDATE' : 0x031D,
    'WM_DWMCOMPOSITIONCHANGED' : 0x031E,
    'WM_DWMNCRENDERINGCHANGED' : 0x031F,
    'WM_DWMCOLORIZATIONCOLORCHANGED' : 0x0320,
    'WM_DWMWINDOWMAXIMIZEDCHANGE' : 0x0321,
    'WM_GETTITLEBARINFOEX' : 0x033F,
    'WM_HANDHELDFIRST' : 0x0358,
    'WM_HANDHELDLAST' : 0x035F,
    'WM_AFXFIRST' : 0x0360,
    'WM_AFXLAST' : 0x037F,
    'WM_PENWINFIRST' : 0x0380,
    'WM_PENWINLAST' : 0x038F,
}
symm(WM_CONSTS)

# Constants for various wParam values
WT_SESSION_PARAM = {
    'WTS_CONSOLE_CONNECT' : 0x1,
    'WTS_CONSOLE_DISCONNECT' : 0x2,
    'WTS_REMOTE_CONNECT' : 0x3,
    'WTS_REMOTE_DISCONNECT' : 0x4,
    'WTS_SESSION_LOGON' : 0x5,
    'WTS_SESSION_LOGOFF' : 0x6,
    'WTS_SESSION_LOCK' : 0x7,
    'WTS_SESSION_UNLOCK' : 0x8,
    'WTS_SESSION_REMOTE_CONTROL' : 0x9,
}
symm(WT_SESSION_PARAM)

WM_DEVICECHANGE_PARAM = {
    'DBT_CONFIGCHANGECANCELED' : 0x0019,
    'DBT_CONFIGCHANGED' : 0x0018,
    'DBT_CUSTOMEVENT' : 0x8006,
    'DBT_DEVICEARRIVAL' : 0x8000,
    'DBT_DEVICEQUERYREMOVE' : 0x8001,
    'DBT_DEVICEQUERYREMOVEFAILED' : 0x8002,
    'DBT_DEVICEREMOVECOMPLETE' : 0x8004,
    'DBT_DEVICEREMOVEPENDING' : 0x8003,
    'DBT_DEVICETYPESPECIFIC' : 0x8005,
    'DBT_DEVNODES_CHANGED' : 0x0007,
    'DBT_QUERYCHANGECONFIG' : 0x0017,
    'DBT_USERDEFINED' : 0xFFFF,
}
symm(WM_DEVICECHANGE_PARAM)

WM_POWERBROADCAST_PARAM = {
    'PBT_APMQUERYSUSPEND' : 0x0000,
    'PBT_APMQUERYSTANDBY' : 0x0001,
    'PBT_APMQUERYSUSPENDFAILED' : 0x0002,
    'PBT_APMQUERYSTANDBYFAILED' : 0x0003,
    'PBT_APMSUSPEND' : 0x0004,
    'PBT_APMSTANDBY' : 0x0005,
    'PBT_APMRESUMECRITICAL' : 0x0006,
    'PBT_APMRESUMESUSPEND' : 0x0007,
    'PBT_APMRESUMESTANDBY' : 0x0008,
    'PBT_APMBATTERYLOW' : 0x0009,
    'PBT_APMPOWERSTATUSCHANGE' : 0x000A,
    'PBT_APMOEMEVENT' : 0x000B,
    'PBT_APMRESUMEAUTOMATIC' : 0x0012,
}
symm(WM_POWERBROADCAST_PARAM)

WM_SIZING_PARAM = {
    'WMSZ_LEFT' : 1,
    'WMSZ_RIGHT' : 2,
    'WMSZ_TOP' : 3,
    'WMSZ_TOPLEFT' : 4,
    'WMSZ_TOPRIGHT' : 5,
    'WMSZ_BOTTOM' : 6,
    'WMSZ_BOTTOMLEFT' : 7,
    'WMSZ_BOTTOMRIGHT' : 8,
}
symm(WM_SIZING_PARAM)

MOUSE_MODS = {
    'MK_LBUTTON' : 0x0001,
    'MK_RBUTTON' : 0x0002,
    'MK_SHIFT' : 0x0004,
    'MK_CONTROL' : 0x0008,
    'MK_MBUTTON' : 0x0010,
    'MK_XBUTTON1' : 0x0020,
    'MK_XBUTTON2' : 0x0040,
}

def WM_WHEEL_PARAM(wParam,horizontal=False):
    from struct import pack, unpack
    
    # Distance is the high word, and is signed
    distance = (wParam & 0xFFFF0000) >> 0x10
    distance = unpack('h',pack('H',distance))[0]

    # Modifiers in the low word
    modifiers = get_flags(MOUSE_MODS, wParam & 0xFFFF)

    if horizontal:
        direction = "RIGHT" if distance > 0 else "LEFT"
    else:
        direction = "UP" if distance > 0 else "DOWN"

    return "%d %s (%s)" % (abs(distance)*120,
                           direction,
                           ",".join(modifiers))

WM_ACTIVATE_PARAM = {
    'WA_INACTIVE' : 0,
    'WA_ACTIVE' : 1,
    'WA_CLICKACTIVE' : 2,
}
symm(WM_ACTIVATE_PARAM)

WM_SIZE_PARAM = {
    'SIZE_RESTORED' : 0,
    'SIZE_MINIMIZED' : 1,
    'SIZE_MAXIMIZED' : 2,
    'SIZE_MAXSHOW' : 3,
    'SIZE_MAXHIDE' : 4,
}
symm(WM_SIZE_PARAM)

# NOTE: There are many more of these; however, I don't have the time to track
#       them down. If you find one missing, add it in and send me a patch!
WPARAM_PARSE = {
    'WM_WTSSESSION_CHANGE' : lambda x: get_const(WT_SESSION_PARAM, x),
    'WM_DEVICECHANGE' : lambda x: get_const(WM_DEVICECHANGE_PARAM, x),
    'WM_POWERBROADCAST' : lambda x: get_const(WM_POWERBROADCAST_PARAM, x),
    'WM_SIZING' : lambda x: get_const(WM_SIZING_PARAM, x),
    'WM_MOUSEWHEEL' : WM_WHEEL_PARAM,
    'WM_MOUSEHWHEEL' : lambda x : WM_WHEEL_PARAM(x,horizontal=True),
    'WM_ACTIVATE' : lambda x : (get_const(WM_ACTIVATE_PARAM,x & 0xFFFF) + "," +
                                "minimized" if x & 0xFFFF0000 else "not minimized"),
    'WM_SIZE' : lambda x: get_const(WM_SIZE_PARAM, x),
}

# Some helper functions
def get_flags(fdict, val):
    """Return the flags a value contains"""
    return [k for k in fdict if f & val]

def get_const(cdict, value, default_fmt="%#010x"):
    """Look up the value of a constant"""
    try:
        return cdict[value]
    except KeyError:
        return default_fmt % value

def parse_param(msgid, param, default_fmt="%#010x"):
    """Parse a wParam"""
    try:
        parser = WPARAM_PARSE[WM_CONSTS[msgid]]
    except KeyError:
        parser = lambda x : default_fmt % param
    return parser(param)

def get_threads(proc):
    """Get a list of all threads for a process"""
    return list_entry(proc.vm, types, proc.profile, 
                      proc.ThreadListHead.v(), "_ETHREAD",
                      fieldname="ThreadListEntry")

class thread_queues(forensics.commands.command):

    # Declare meta information associated with this plugin
    
    meta_info = forensics.commands.command.meta_info 
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def help(self):
        return  "Print message queues for each thread"
    
    def print_message_queue(self, thrd):
        w32thread = thrd.Tcb.Win32Thread
        if not w32thread.is_valid() or w32thread.offset < 0x80000000:
            return
        print "Thread %x:%x (%s) -- %d messages" % (thrd.Cid.UniqueProcess.v(),
                                                    thrd.Cid.UniqueThread.v(),
                                                    thrd.ThreadsProcess.ImageFileName,
                                                    w32thread.MsgQueue.Count)

        if not w32thread.MsgQueue.Head.is_valid() or not w32thread.MsgQueue.Count:
            return

        # There has to be a better way to pretty-print these
        cur = w32thread.MsgQueue.Head
        while True:
            print "  %-5s %-12s %8s %-32s %8s %-12s" % (
                                             "hWnd:","[%#010x]" % cur.Msg.hWnd,
                                             "Message:", "[%s]" % get_const(WM_CONSTS,cur.Msg.ulMsg),
                                             "cursor:", "(%d,%d)" % (cur.Msg.pt.x,cur.Msg.pt.y),
                                             )
            print "  %-5s %-12s %8s %-32s %8s %-12s" % (
                                             "","",
                                             "wParam:", "[%s]"  % parse_param(cur.Msg.ulMsg, cur.Msg.wParam),
                                             "lParam:", "[%#010x]"  % cur.Msg.lParam,
                                             )
            print "  %-5s %-12s %8s %-32s %8s %-12s" % (
                                             "","",
                                             "dwUnk:", "[%#010x]" % cur.Msg.dwUnknown,
                                             "dwExtra:", "[%#010x]" % cur.Msg.dwExtraInfo,
                                             )
            print "  %-5s %-12s %8s %-32s" % (
                                             "","",
                                             "time:", "%s" % timedelta(milliseconds=cur.Msg.time),
                                             )
                                       
            if cur.pNext.is_valid():
                cur = cur.pNext
            else:
                break

    def execute(self):
        from vtypes import xpsp2types
        
        xpsp2types['_ETHREAD'][1]['ThreadListEntry'] = [ 0x22c, ['_LIST_ENTRY']]
        xpsp2types['_KTHREAD'][1]['Win32Thread'] = [ 0x130, ['pointer', ['_W32THREAD']]]

        theProfile = Profile()
        theProfile.add_types(gdi_types)

        (addr_space, symtab, types) = load_and_identify_image(self.op,
            self.opts)
        pslist = process_list(addr_space, types, symtab)
        pslist = [Object('_EPROCESS', p, addr_space, profile=theProfile) for p in pslist]

        for p in pslist:
            for t in get_threads(p):
                self.print_message_queue(t)
