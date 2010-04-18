#-----------------------------------------------------------
# comdlg32.pl
# Plugin for Registry Ripper 
#
# Change history
#
#
# References
#   Win2000 - http://support.microsoft.com/kb/319958
#   XP - http://support.microsoft.com/kb/322948/EN-US/
#		
# copyright 2008 H. Carvey
#-----------------------------------------------------------
package comdlg32;
use strict;

my %config = (hive          => "NTUSER\.DAT",
              hasShortDescr => 1,
              hasDescr      => 0,
              hasRefs       => 0,
              osmask        => 22,
              version       => 20080324);

sub getConfig{return %config}
sub getShortDescr {
	return "Gets contents of user's ComDlg32 key";
}
sub getDescr{}
sub getRefs {}
sub getHive {return $config{hive};}
sub getVersion {return $config{version};}

my $VERSION = getVersion();

sub pluginmain {
	my $class = shift;
	my $ntuser = shift;
	::logMsg("Launching comdlg32 v.".$VERSION);
	my $reg = Parse::Win32Registry->new($ntuser);
	my $root_key = $reg->get_root_key;
	::rptMsg("comdlg32 v.".$VERSION);
	
# LastVistedMRU	
	my $key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU";
	my $key;
	my @vals;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("ComDlg32\\LastVisitedMRU");
		::rptMsg("**All values printed in MRUList order.");
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
		
		my %lvmru;
		my @mrulist;
		@vals = $key->get_list_of_values();
		
		if (scalar(@vals) > 0) {
# First, read in all of the values and the data
			foreach my $v (@vals) {
				$lvmru{$v->get_name()} = $v->get_data();
			}
# Then, remove the MRUList value
			if (exists $lvmru{MRUList}) {
				::rptMsg("\tMRUList = ".$lvmru{MRUList});
				@mrulist = split(//,$lvmru{MRUList});
				delete($lvmru{MRUList});
				foreach my $m (@mrulist) {
					my ($file,$dir) = split(/\00\00/,$lvmru{$m},2);
					$file =~ s/\00//g;
					$dir  =~ s/\00//g;
					::rptMsg("\t".$m." -> ".$dir."\\".$file);
				}
			}
			else {
				::rptMsg($key_path." does not have an MRUList value.");
			}				
		}
		else {
			::rptMsg($key_path." has no values.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
	::rptMsg("");
	
# OpenSaveMRU	
	my $key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU";
	my $key;
	my @vals;
	if ($key = $root_key->get_subkey($key_path)) {
		::rptMsg("ComDlg32\\OpenSaveMRU");
		::rptMsg("**All values printed in MRUList order.");
		::rptMsg($key_path);
		::rptMsg("LastWrite Time ".gmtime($key->get_timestamp())." (UTC)");
# First, let's get the values
		my %osmru;		
		my @vals = $key->get_list_of_values();
		if (scalar(@vals) > 0) {
			map{$osmru{$_->get_name()} = $_->get_data()}(@vals);
			if (exists $osmru{MRUList}) {
				::rptMsg("\tMRUList = ".$osmru{MRUList});
				my @mrulist = split(//,$osmru{MRUList});
				delete($osmru{MRUList});
				foreach my $m (@mrulist) {
					::rptMsg("\t".$m." -> ".$osmru{$m});
				}
			}
			else {
				::rptMsg($key_path." does not have an MRUList value.");
			}	
		}
		else {
			::rptMsg($key_path." has no values.");
		}
		::rptMsg("");
# Now, let's get the subkeys
		my @sk = $key->get_list_of_subkeys();
		if (scalar(@sk) > 0) {
			foreach my $s (@sk) {
				::rptMsg("Subkey: ".$s->get_name());
				::rptMsg("LastWrite Time ".gmtime($s->get_timestamp())." (UTC)");
				my %mru;
				my @vals = $s->get_list_of_values();
				if (scalar(@vals) > 0) {
					map{$mru{$_->get_name()} = $_->get_data()}(@vals);
					if (exists $mru{MRUList}) {
						::rptMsg("\t\tMRUList = ".$mru{MRUList});
						my @mrulist = split(//,$mru{MRUList});
						delete($mru{MRUList});
						foreach my $m (@mrulist) {
							::rptMsg("\t\t".$m." -> ".$mru{$m});
						}
					}
					else {
						::rptMsg($key_path."\\".$s->get_name()." does not have an MRUList value.");
					}	
				}
				else {
					::rptMsg($key_path."\\".$s->get_name()." has no values.");
				}
				::rptMsg("");
			}
		}
		else {
			::rptMsg($key_path." has no subkeys.");
		}
	}
	else {
		::rptMsg($key_path." not found.");
	}
}	
1;		