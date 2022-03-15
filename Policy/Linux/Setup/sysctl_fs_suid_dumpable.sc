if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150144" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-03-04 15:25:10 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: sysctl fs.suid_dumpable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_and_parse_sysctl.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "0;1", id: 1 );
	script_xref( name: "URL", value: "https://www.cyberciti.biz/faq/linux-disable-core-dumps/" );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/sysctl" );
	script_tag( name: "summary", value: "Core dumps are the memory of a process when it crashes. Core
dumps can grow to significant size, ending in a Denial of Service. Also, core dumps can be used to
get confidential information from a core file.

Note: This scripts looks for 'fs.suid_dumpable' setting in 'sysctl -a'." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "sysctl fs.suid_dumpable";
title = "sysctl fs.suid_dumpable";
solution = "sysctl -w fs.suid_dumpable = [0,1]";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "Policy/linux/sysctl/ssh/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host";
}
else {
	if( get_kb_item( "Policy/linux/sysctl/ERROR" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not run sysctl command";
	}
	else {
		if( !value = get_kb_item( "Policy/linux/sysctl/fs.suid_dumpable" ) ){
			value = "Error";
			compliant = "incomplete";
			comment = "Could not find setting with sysctl.";
		}
		else {
			compliant = policy_setting_exact_match( value: value, set_point: default );
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

