if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150226" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-05-07 06:49:26 +0000 (Thu, 07 May 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: SSH StrictModes" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_sshd_config.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "yes;no", id: 1 );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/sshd_config" );
	script_tag( name: "summary", value: "sshd reads configuration data from /etc/ssh/sshd_config (or the
file specified with -f on the command line). The file contains keyword-argument pairs, one per line.
Lines starting with '#' and empty lines are interpreted as comments. Arguments may optionally be
enclosed in double quotes in order to represent arguments containing spaces.

  - StrictModes: Specifies whether sshd should check file modes and ownership of the user's files and
home directory before accepting login. This is normally desirable because novices sometimes
accidentally leave their directory or files world-writable." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "grep '^StrictModes' /etc/ssh/sshd_config";
title = "SSH StrictModes";
solution = "Edit /etc/ssh/sshd_config";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "linux/mount/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Could not read /etc/ssh/sshd_config";
}
else {
	value = get_kb_item( "Policy/linux/sshd_config/strictmodes" );
	compliant = policy_setting_exact_match( value: value, set_point: default );
	comment = "";
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );
