if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150063" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-01-10 10:33:06 +0100 (Fri, 10 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Separate partition for /var/log/audit" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "linux_list_mounted_filesystems.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Separate partition", type: "radio", value: "yes;no", id: 1 );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/mount" );
	script_tag( name: "summary", value: "The /var/log/audit directory is used by auditd.

This script tests if a separate partition exists for /var/log/audit." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
cmd = "mount | grep /var/log/audit";
title = "Separate partition for /var/log/audit";
solution = "Create a new partition and configure /var/log/audit as appropriate";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Separate partition", id: 1 );
if( get_kb_item( "linux/mount/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Could not get information about mounted partitions";
}
else {
	mounted_partitions = get_kb_list( "linux/mount/device" );
	if( !in_array( search: "/var/log/audit", array: mounted_partitions, part_match: FALSE ) ) {
		value = "no";
	}
	else {
		value = "yes";
	}
	compliant = policy_setting_exact_match( value: value, set_point: default );
	comment = "";
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

