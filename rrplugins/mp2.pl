#-----------------------------------------------------------
# mp2.pl
# Plugin for Registry Ripper,
# MountPoints2 key parser
#
# Change history
#
#
# References
#
# 
# copyright 2008 H. Carvey
#-----------------------------------------------------------
package mp2;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20080324);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets user's MountPoints2 key contents";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching mp2 v.".$VERSION);
	
	my %drives;
	my %volumes;
	my %remote;
	
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("MountPoints2");
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar @subkeys > 0) {
			foreach my $s (@subkeys) {
				my $name = $s->get_name();
				if ($name =~ m/^{/) {
					$volumes{$name} = $s->get_timestamp();
				}
				elsif ($name =~ m/^[A-Z]/) {
					$drives{$name} = $s->get_timestamp();
				}
				elsif ($name =~ m/^#/) {
					$remote{$name} = $s->get_timestamp();
				}
				else {
					::rptMsg("  Key name = ".$name);
				}
			}
			
			::rptMsg("");
			::rptMsg("  Drives:");
			foreach my $d (keys %drives) {
				::rptMsg("    ".$d."  ".gmtime($drives{$d})." (UTC)");
			}
			::rptMsg("");
			::rptMsg("  Volumes:");
			foreach my $v (keys %volumes) {
				::rptMsg("    ".$v."  ".gmtime($volumes{$v})." (UTC)");
			}
			::rptMsg("");
			::rptMsg("  Remote Drives:");
			foreach my $r (keys %remote) {
				::rptMsg("    ".$r."  ".gmtime($remote{$r})." (UTC)");
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
			::logMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
		::logMsg($key_path." not found.");
	}
}

1;