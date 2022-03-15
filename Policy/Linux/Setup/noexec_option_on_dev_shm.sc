if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150318" );
	script_version( "2021-05-14T14:03:39+0000" );
	script_tag( name: "last_modification", value: "2021-05-14 14:03:39 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "creation_date", value: "2020-11-04 15:27:46 +0000 (Wed, 04 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: noexec option on /dev/shm" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "linux_list_mounted_filesystems.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/mount" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 1.1.17 Ensure noexec option set on /dev/shm partition (Scored)" );
	script_xref( name: "Policy", value: "CIS CentOS Linux 8 Benchmark v1.0.0: 1.1.17 Ensure noexec option set on /dev/shm partition (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 2.6 Address unapproved software" );
	script_tag( name: "summary", value: "The noexec mount option specifies that the filesystem cannot
contain executable binaries.

Setting this option on a file system prevents users from executing programs from shared memory. This
deters users from introducing potentially malicious software on the system." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "mount | grep -E '\\s/dev/shm\\s' | grep -v noexec";
title = "Option 'noexec' is set on /dev/shm";
solution = "mount -o remount,noexec /dev/shm";
test_type = "SSH_Cmd";
default = "Enabled";
if( get_kb_item( "linux/mount/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Could not get information about partitions";
}
else {
	if( !options = get_kb_item( "linux/mount//dev/shm/options" ) ){
		value = "Disabled";
		compliant = "no";
		comment = "No separate /dev/shm partition found";
	}
	else {
		if( IsMatchRegexp( options, "noexec" ) ) {
			value = "Enabled";
		}
		else {
			value = "Disabled";
		}
		compliant = policy_setting_exact_match( value: value, set_point: default );
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

