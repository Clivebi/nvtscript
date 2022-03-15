if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150157" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-03-11 14:46:32 +0000 (Wed, 11 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: FAILLOG_ENAB in /etc/login.defs" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_etc_login_defs.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "yes;no", id: 1 );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/login.defs" );
	script_tag( name: "summary", value: "FAILLOG_ENAB variable enables logging and display of
/var/log/faillog login failure info." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "grep 'FAILLOG_ENAB' /etc/login.defs";
title = "Enable logging and display of /var/log/faillog login failure info";
solution = "Add 'FAILLOG_ENAB [yes|no]' to /etc/login.defs";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "Policy/linux//etc/login.defs/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host";
}
else {
	if( get_kb_item( "Policy/linux//etc/login.defs/content/ERROR" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not read /etc/login.defs";
	}
	else {
		content = get_kb_item( "Policy/linux//etc/login.defs/content" );
		grep = egrep( string: content, pattern: "FAILLOG_ENAB" );
		if( IsMatchRegexp( grep, "^\\s*#" ) || IsMatchRegexp( grep, "FAILLOG_ENAB\\s+no" ) || !grep ) {
			value = "no";
		}
		else {
			value = "yes";
		}
		compliant = policy_setting_exact_match( value: value, set_point: default );
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

