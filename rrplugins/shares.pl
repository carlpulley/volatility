#-----------------------------------------------------------
# shares
#
# copyright 2008 H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package shares;
use strict;

my %config = (hive          => "System",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 200800420);

sub getConfig{return %config}

sub getShortDescr {
	return "Get list of shares from System hive file";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching shares v.".$VERSION);
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

# Code for System file, getting CurrentControlSet
 	my $current;
 	my $ccs;
 	eval {
		my $key_path = 'Select';
		my $key;
		if ($key = $root_key->get_subkey($key_path)) {
			$current = $key->get_value("Current")->get_data();
			$ccs = "ControlSet00".$current;
		}
	};
	if ($@) {
		::rptMsg("Problem locating proper controlset: $@");
		return;
	}

	my $key_path = $ccs."\\Services\\lanmanserver\\Shares";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		::rptMsg("");
		my @vals = $key->get_list_of_values();
		if (scalar(@vals) > 0) {
			foreach my $v (@vals) {
				::rptMsg($v->get_name());
				my @items = $v->get_data();
				foreach my $i (@items) {
#					$i =~ s/\00//g;
					::rptMsg("  ".$i);
				}
			}
			::rptMsg("");
		}
		else {
			::rptMsg($key_path." has no values.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
		::logMsg($key_path." not found.");
	}
}
1;
