#-----------------------------------------------------------
# profilelist.pl
# Gets ProfileList subkeys and ProfileImagePath value; also
# gets the ProfileLoadTimeHigh and Low values, and translates them
# into a readable time
#
# copyright 2008 H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package profilelist;
use strict;

my %config = (hive          => "Software",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20080415);

sub getConfig{return %config}

sub getShortDescr {
	return "Get content of ProfileList key";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching profilelist v.".$VERSION);
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key_path = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		::rptMsg("");
		
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) {
				my $path;
				eval {
					$path = $s->get_value("ProfileImagePath")->get_data();
				};
				::rptMsg("Path      : ".$path);
				::rptMsg("SID       : ".$s->get_name());
				::rptMsg("LastWrite : ".gmtime($s->get_timestamp())." (UTC)");
				
				my @load;
				eval {
					$load[0] = $s->get_value("ProfileLoadTimeLow")->get_data();
					$load[1] = $s->get_value("ProfileLoadTimeHigh")->get_data();
				};
				if (@load) {
					my $loadtime = ::getTime($load[0],$load[1]);
					::rptMsg("LoadTime  : ".gmtime($loadtime)." (UTC)");
				}
				::rptMsg("");
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