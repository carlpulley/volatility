#-----------------------------------------------------------
# adoberdr.pl
# Plugin for Registry Ripper 
# Parse Adobe Reader MRU keys
#
# Change history
#
#
# References
#
# Note: LastWrite times on c subkeys will all be the same,
#       as each subkey is modified as when a new entry is added
#
# copyright 2008 H. Carvey
#-----------------------------------------------------------
package adoberdr;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20080324);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets user's Adobe Reader cRecentFiles values";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching adoberdr v.".$VERSION);
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;
	::rptMsg("Adoberdr v.".$VERSION);
# First, let's find out which version of Adobe Acrobat Reader is installed
	my $version;
	my $tag = 0;
	my @versions = ("6\.0","7\.0","8\.0");
	foreach my $ver (@versions) {		
		my $key_path = "Software\\Adobe\\Acrobat Reader\\".$ver."\\AVGeneral\\cRecentFiles";
		if (defined($root_key->get_subkey($key_path))) {
			$version = $ver;
			$tag = 1;
		}
	}
	
	if ($tag) {
		::rptMsg("Adobe Acrobat Reader version ".$version." located."); 
		my $key_path = "Software\\Adobe\\Acrobat Reader\\".$version."\\AVGeneral\\cRecentFiles";   
		my $key = $root_key->get_subkey($key_path);
		if ($key) {
			::rptMsg($key_path);
			::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
			my %arkeys;
			my @subkeys = $key->get_list_of_subkeys();
			if (scalar @subkeys > 0) {
				foreach my $s (@subkeys) {
					my $num = $s->get_name();
					my $data = $s->get_value('sDI')->get_data();
					$num =~ s/^c//;
					$arkeys{$num}{lastwrite} = $s->get_timestamp();
					$arkeys{$num}{data} = $data;
				}
				
				foreach my $k (sort keys %arkeys) {
					::rptMsg("c".$k."   ".gmtime($arkeys{$k}{lastwrite})."  ".$arkeys{$k}{data});
				}

			}
			else {
				::rptMsg($key_path." has no subkeys.");
				::logMsg($key_path." has no subkeys.");
			}
		}
		else {
			::rptMsg("Could not access ".$key_path);
			::logMsg("Could not access ".$key_path);
		}
	}
	else {
		::logMsg("Adobe Acrobat Reader version not found.");
		::rptMsg("Adobe Acrobat Reader version not found.");
	}
}

1;