#-----------------------------------------------------------
# uninstall.pl
# Gets contents of Uninstall key from Software hive; sorts 
# display names based on key LastWrite time
#
# copyright 2008 H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package uninstall;
use strict;

my %config = (hive          => "Software",
              osmask        => 22,
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              version       => 20080331);

sub getConfig{return %config}

sub getShortDescr {
	return "Gets contents of Uninstall key from Software hive";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching uninstall v.".$VERSION);
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;

	my $key_path = 'Microsoft\\Windows\\CurrentVersion\\Uninstall';
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("Uninstall");
		::rptMsg($key_path);
		::rptMsg("");
		
		my %uninst;
		my @subkeys = $key->get_list_of_subkeys();
	 	if (scalar(@subkeys) > 0) {
	 		foreach my $s (@subkeys) {
	 			my $lastwrite = $s->get_timestamp();
	 			my $display;
	 			eval {
	 				$display = $s->get_value("DisplayName")->get_data();
	 			};
	 			$display = $s->get_name() if ($display eq "");
	 			push(@{$uninst{$lastwrite}},$display);
	 		}
	 		foreach my $t (reverse sort {$a <=> $b} keys %uninst) {
				::rptMsg(gmtime($t)." (UTC)");
				foreach my $item (@{$uninst{$t}}) {
					::rptMsg("\t$item");
				}
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