if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150127" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-02-05 08:52:42 +0100 (Wed, 05 Feb 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: /etc/login.defs LASTLOG_ENAB" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_etc_login_defs.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "Yes;No", id: 1 );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/login.defs" );
	script_tag( name: "summary", value: "The /etc/login.defs file defines the site-specific configuration
for the shadow password suite. This file is required. Absence of this file will not prevent system
operation, but will probably result in undesirable operation.

LASTLOG_ENAB (boolean) enables logging and display of /var/log/lastlog login time info." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "grep '^LASTLOG_ENAB' /etc/login.defs";
title = "LASTLOG_ENAB setting in /etc/login.defs";
solution = "Edit /etc/login.defs";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "Policy/linux//etc/login.defs/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Could not access host";
}
else {
	if( get_kb_item( "Policy/linux//etc/login.defs/content/ERROR" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Could not read /etc/login.defs";
	}
	else {
		etc_login_defs_content = get_kb_item( "Policy/linux//etc/login.defs/content" );
		line = egrep( string: etc_login_defs_content, pattern: "^\\s*LASTLOG_ENAB" );
		if( line ){
			value = eregmatch( string: line, pattern: "^\\s*LASTLOG_ENAB\\s*(.*)" );
			value = chomp( value[1] );
		}
		else {
			value = "None";
		}
		compliant = policy_setting_exact_match( value: tolower( value ), set_point: tolower( default ) );
		comment = "";
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

