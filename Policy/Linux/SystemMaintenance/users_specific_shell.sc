if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150108" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-01-29 12:42:17 +0100 (Wed, 29 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: User accounts with non-specific shells" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_passwd_file.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "entry", value: "/bin/bash,/bin/csh,/bin/jsh,/bin/ksh,/bin/rbash,/bin/sh,/bin/tcsh,/bin/zsh,/bin/false,/usr/bin/bash,/sbin/jsh,/sbin/sh,/usr/bin/csh,/usr/bin/jsh,/usr/bin/ksh,/usr/bin/sh,/usr/bin/rksh,/usr/bin/tcsh,/usr/sbin/ksh", id: 1 );
	script_tag( name: "summary", value: "The password file stores information about users such like
username, UID, GID, etc." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "cat /etc/passwd";
title = "User accounts with non-specific shells";
solution = "Change entry in /etc/passwd to a specific shell";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
comment = "";
if( !get_kb_item( "login/SSH/success" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection";
}
else {
	if( get_kb_item( "Policy/linux//etc/passwd/content/ERROR" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not read /etc/passwd";
	}
	else {
		passwd_content = get_kb_item( "Policy/linux//etc/passwd/content" );
		for line in split( buffer: passwd_content, keep: FALSE ) {
			entries = split( buffer: line, sep: ":", keep: FALSE );
			user = entries[0];
			uid = entries[2];
			shell = entries[6];
			if(int( uid ) >= 1000 && int( uid ) <= 60000){
				if(!ContainsString( default, shell )){
					value += "," + user;
				}
			}
		}
		if( value ){
			compliant = "no";
			value = str_replace( string: value, find: ",", replace: "", count: 1 );
		}
		else {
			compliant = "yes";
			value = "None";
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

