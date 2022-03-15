if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150153" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-03-10 10:00:27 +0000 (Tue, 10 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Time default value for tcp_fin_timeout connection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_etc_sysctl_d.sc", "read_and_parse_sysctl.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "entry", value: "60", id: 1 );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/sysctl.conf" );
	script_xref( name: "URL", value: "https://easyengine.io/tutorials/linux/sysctl-conf/" );
	script_tag( name: "summary", value: "This setting aims to protect the system against DoS attacks
due to a large TIME_WAIT value." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "sysctl net.ipv4.tcp_fin_timeout";
title = "Time default value for tcp_fin_timeout connection";
solution = "sysctl -w net.ipv4.tcp_fin_timeout = VALUE";
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
		value = get_kb_item( "Policy/linux/sysctl/net.ipv4.tcp_fin_timeout" );
		if( !value ){
			value = "Error";
			compliant = "incomplete";
			comment = "Could not find setting with sysctl";
		}
		else {
			compliant = policy_setting_exact_match( value: value, set_point: default );
		}
		if( get_kb_item( "Policy/linux/sysctl/conf/ERROR" ) ){
			comment = "No SSH connection to host to read /etc/sysctl config files.";
		}
		else {
			files = make_list( "/etc/sysctl.conf",
				 get_kb_list( "Policy/linux//etc/sysctl.d//files/" ) );
			for file in files {
				if(get_kb_item( "Policy/linux/" + file + "/content/ERROR" )){
					continue;
				}
				content = get_kb_item( "Policy/linux/" + file + "/content" );
				grep_pattern = egrep( string: content, pattern: "net.ipv4.tcp_fin_timeout" );
				if(grep_pattern){
					grep_pattern = str_replace( string: grep_pattern, find: "\r\n", replace: " " );
					comment += ", " + file + ": " + chomp( grep_pattern );
				}
			}
			if( comment ) {
				comment = str_replace( string: comment, find: ", ", replace: "", count: 1 );
			}
			else {
				comment = "Could not find setting in any sysctl config file";
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

