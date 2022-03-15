if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150560" );
	script_version( "2021-01-15T14:47:13+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 14:47:13 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-15 13:47:26 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: SSH RekeyLimit" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_sshd_config.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "entry", value: "1G 1h", id: 1 );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/sshd_config" );
	script_tag( name: "summary", value: "sshd reads configuration data from /etc/ssh/sshd_config (or the
file specified with -f on the command line). The file contains keyword-argument pairs, one per line.
Lines starting with '#' and empty lines are interpreted as comments. Arguments may optionally be
enclosed in double quotes in order to represent arguments containing spaces.

RekeyLimit specifies the maximum amount of data that may be transmitted before the session key is
renegotiated, optionally followed a maximum amount of time that may pass before the session key is
renegotiated." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
cmd = "grep '^RekeyLimit' /etc/ssh/sshd_config";
title = "SSH RekeyLimit";
solution = "Edit /etc/ssh/sshd_config";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "Policy/linux/sshd_config/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Could not read /etc/ssh/sshd_config";
}
else {
	if( !value = get_kb_item( "Policy/linux/sshd_config/rekeylimit" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Could not get supported RekeyLimit from /etc/ssh/sshd_config";
	}
	else {
		compliant = policy_setting_exact_match( value: value, set_point: default );
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

