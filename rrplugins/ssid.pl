#-----------------------------------------------------------
# ssid
#
# copyright 2008 H. Carvey, keydet89@yahoo.com
#-----------------------------------------------------------
package ssid;
use strict;

my %config = (hive          => "Software",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20080327);

sub getConfig{return %config}
sub getShortDescr {
	return "Get WZCSVC SSID Info";	
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();
my $error;

sub pluginmain {
	my $class = shift;
	my $hive = shift;
	::logMsg("Launching ssid v.".$VERSION);
# Get the NetworkCards values
	my %nc;
	if (%nc = getNetworkCards($hive)) {
		
	}
	else {
		::logMsg("Problem w/ SSIDs, getting NetworkCards: ".$error);
		return;
	}
		
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key_path = "Microsoft\\WZCSVC\\Parameters\\Interfaces";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("SSID");
		::rptMsg($key_path);
		::rptMsg("");
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) {
				my $name = $s->get_name();
				if (exists($nc{$name})) {
					::rptMsg("NIC: ".$nc{$name}{descr});
					my @vals = $s->get_list_of_values();
					if (scalar(@vals) > 0) {
						foreach my $v (@vals) {
							my $n = $v->get_name();
							if ($n =~ m/^Static#/) {
								my $data = $v->get_data();
								my $ssid = substr($data,0x14,0x20);
								$ssid =~ s/\00//g;
								my ($t1,$t2) = unpack("VV",substr($data,0x2B8,8));
								my $t        = ::getTime($t1,$t2);
								
								::rptMsg("  ".$n." SSID : ".$ssid." [".gmtime($t)."]");
								
							}
						}
					}
					else {
						::rptMsg($name." has no values.");
					}
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

sub getNetworkCards {
	my $hive = shift;
	my %nc;
	my $reg = Parse::Win32Registry->new($hive);
	my $root_key = $reg->get_root_key;
	my $key_path = "Microsoft\\Windows NT\\CurrentVersion\\NetworkCards";
	my $key;
	if ($key = $root_key->get_subkey($key_path)) {
		my @subkeys = $key->get_list_of_subkeys();
		if (scalar(@subkeys) > 0) {
			foreach my $s (@subkeys) {
				my $service = $s->get_value("ServiceName")->get_data();
				$nc{$service}{descr} = $s->get_value("Description")->get_data();
				$nc{$service}{lastwrite} = $s->get_timestamp();
			}
		}
		else {
			$error = $key_path." has no subkeys.";
		}
	}
	else {
		$error = $key_path." not found.";
	}
	return %nc;
}

1;