if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150263" );
	script_version( "2020-07-29T07:27:10+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 07:27:10 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-06-09 12:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Blacklisted binaries" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "ssh_authorization.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Blacklist", type: "entry", value: "binary1,binary2", id: 1 );
	script_tag( name: "summary", value: "Some binaries have security issues or should not be available
on the host for other reasons.

This script checks if any of the given binaries is installed on the host by using locate, whereis or which." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
cmd = "[locate,whereis,which] BINARY";
title = "Blacklisted Binaries";
solution = "Disable Binary";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Blacklist", id: 1 );
if( !get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection() ){
	value = "Error";
	compliant = "incomplete";
	note = "No SSH connection possible";
}
else {
	blacklist = policy_build_list_from_string( str: default );
	for bin in blacklist {
		if(ssh_find_bin( prog_name: bin, sock: sock )){
			value += "," + bin;
		}
	}
	if( value ){
		value = str_replace( string: value, find: ",", replace: "", count: 1 );
		compliant = "no";
	}
	else {
		compliant = "yes";
		value = "None";
	}
	note = "";
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: note );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

