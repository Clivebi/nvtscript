if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150084" );
	script_version( "2021-01-19T07:18:36+0000" );
	script_tag( name: "last_modification", value: "2021-01-19 07:18:36 +0000 (Tue, 19 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-01-16 11:40:56 +0100 (Thu, 16 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: SSH /etc/ssh/sshd_config chown" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_sshd_config.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "entry", value: "root:root", id: 1 );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/sshd_config" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 5.1 Establish Secure Configurations" );
	script_tag( name: "summary", value: "sshd reads configuration data from /etc/ssh/sshd_config (or the
file specified with -f on the command line). The file contains keyword-argument pairs, one per line.
Lines starting with '#' and empty lines are interpreted as comments. Arguments may optionally be
enclosed in double quotes in order to represent arguments containing spaces." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
cmd = "stat /etc/ssh/sshd_config";
title = "SSH /etc/ssh/sshd_config chown";
solution = "chown PERMISSION /etc/ssh/sshd_config";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "Policy/linux/sshd_config/stat/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Could not get information about /etc/ssh/sshd_config";
}
else {
	stat = get_kb_item( "Policy/linux/sshd_config/stat" );
	uid = policy_chown_get_uid( stat: stat );
	gid = policy_chown_get_gid( stat: stat );
	value = uid + ":" + gid;
	compliant = policy_setting_exact_match( value: value, set_point: default );
	comment = "";
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

