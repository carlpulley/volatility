#-----------------------------------------------------------
# cmd_shell
#
#
#-----------------------------------------------------------
package cmd_shell;
use strict;

my %config = (hive          => "Software",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 1,
              version       => 20080328);

sub getConfig{return %config}

sub getShortDescr {
	return "Gets shell open cmds for various file types";	
}
sub getDescr{}
sub getRefs {
	my %refs = ("You Are Unable to Start a Program with an .exe File Extension" =>
	            "http://support.microsoft.com/kb/310585");
	return %refs;	
}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching cmd_shell v.".$VERSION);
	
	my @shells = ("exe","cmd","bat","hta","pif");
	
	foreach my $sh (@shells) {
		
		my $reg = Parse::Win32Registry->new($hive);
		my $root_key = $reg->get_root_key;

		my $key_path = "Classes\\".$sh."file\\shell\\open\\command";
		my $key;
		if ($key = $root_key->get_subkey($key_path)) {
			::rptMsg($key_path);
			::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
			my $val;
			eval {
				$val = $key->get_value("")->get_data();
				::rptMsg("\tCmd: ".$val);
			};
			::rptMsg("Error: ".$@) if ($@);
		
		}
		else {
			::rptMsg($key_path." not found.");
			::logMsg($key_path." not found.");
		}
	}
	::rptMsg("");
}
1;