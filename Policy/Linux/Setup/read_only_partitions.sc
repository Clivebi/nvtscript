if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150100" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-01-23 14:33:52 +0100 (Thu, 23 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: List partitions mounted in read only mode" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "linux_list_mounted_filesystems.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/mount" );
	script_tag( name: "summary", value: "Mounting partitions in read-only mode prevent files from being
modified.

Note that, depending on the filesystem type, state and kernel behavior, the system may still write
to the device. For example, Ext3 or ext4 will replay its journal if the filesystem is dirty. To
prevent this kind of write access, you may want to mount ext3 or ext4 filesystem with 'ro, noload'
mount options or set the block device to read-only mode.

Note: This script lists all partitions mounted in 'ro' mode." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
cmd = "mount | grep -w ro";
title = "List partitions mounted in read only mode";
solution = "mount -o remount,ro PARTITION";
test_type = "Manual Check";
default = "None";
compliant = "yes";
if( get_kb_item( "linux/mount/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Could not get information about partitions";
}
else {
	partitions = get_kb_list( "linux/mount/device" );
	for partition in partitions {
		options = get_kb_item( "linux/mount/" + partition + "/options" );
		options_list = split( buffer: options, sep: ",", keep: FALSE );
		if(in_array( search: "ro", array: options_list )){
			value += "," + partition;
		}
	}
	if( value ) {
		value = str_replace( string: value, find: ",", replace: "", count: 1 );
	}
	else {
		value = "None";
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

