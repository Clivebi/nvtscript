if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150168" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-03-17 10:52:32 +0000 (Tue, 17 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: kern.* in /etc/rsyslog.conf" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_etc_rsyslog_conf.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/rsyslog.conf" );
	script_add_preference( name: "Value", type: "entry", value: "/var/log/kernel.log", id: 1 );
	script_tag( name: "summary", value: "Log all kernel events to local log file." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "grep 'kern.*' /etc/rsyslog.conf";
title = "kern.* in /etc/rsyslog.conf";
solution = "Add 'kern.* FILE' to /etc/rsyslog.conf";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "Policy/linux//etc/rsyslog.conf/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host";
}
else {
	if( get_kb_item( "Policy/linux//etc/rsyslog.conf/content/ERROR" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not read /etc/rsyslog.conf";
	}
	else {
		content = get_kb_item( "Policy/linux//etc/rsyslog.conf/content" );
		grep = egrep( string: content, pattern: "kern\\.\\*" );
		if(grep){
			for line in split( grep ) {
				if(IsMatchRegexp( line, "^\\s*#" )){
					continue;
				}
				file = eregmatch( string: line, pattern: "kern\\.\\*\\s+(.+)" );
				if(file){
					value += "," + chomp( file[1] );
				}
			}
		}
		if(value){
			value = str_replace( string: value, find: ",", replace: "", count: 1 );
		}
		if(!value){
			value = "None";
			comment = "Can not find kern.emerg in /etc/rsyslog.conf";
		}
		compliant = policy_settings_lists_match( value: value, set_points: default, sep: "," );
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

