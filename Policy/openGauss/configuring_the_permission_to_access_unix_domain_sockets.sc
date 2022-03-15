if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150339" );
	script_version( "2020-11-12T12:33:52+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 12:33:52 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-11 15:21:37 +0000 (Wed, 11 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "openGauss: Configuring the Permission to Access UNIX Domain Sockets" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gb_huawei_opengauss_ssh_login_detect.sc", "compliance_tests.sc", "opengauss_authentication_information.sc" );
	script_mandatory_keys( "huawei/opengauss/detected", "Compliance/Launch" );
	script_xref( name: "URL", value: "https://opengauss.org" );
	script_tag( name: "summary", value: "unix_socket_permissions specifies the permission to access UNIX domain sockets.
The default value of this parameter is 0777, indicating that all users can access
UNIX domain sockets. You are advised to set this parameter to 0770 (indicating
that only users and groups can access UNIX domain sockets) or 0700 (indicating
that only users can access UNIX domain sockets)." );
	exit( 0 );
}
require("policy_functions.inc.sc");
require("ssh_func.inc.sc");
cmd = "SELECT name,setting FROM pg_settings WHERE name = 'unix_socket_permissions';";
title = "Configuring the Permission to Access UNIX Domain Sockets";
solution = "Set unix_socket_permissions to 0770 in the postgresql.conf file and then restart the database.";
default = "0770 or 0700";
test_type = "SQL_Query";
if( !get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection() ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( !value = policy_gsql_cmd( socket: sock, query: cmd ) ){
		compliant = "incomplete";
		value = "error";
		comment = "SQL command did not return anything";
	}
	else {
		if( IsMatchRegexp( value, "failed to connect" ) ){
			compliant = "incomplete";
			value = "error";
			comment = "No connection to database";
		}
		else {
			value = ereg_replace( string: chomp( value ), pattern: "^\\s+", replace: "" );
			setting = eregmatch( string: value, pattern: "unix_socket_permissions\\s+\\|\\s+([0-9]+)" );
			if( !setting[1] ){
				compliant = "incomplete";
				comment = "Can not determine setting.";
			}
			else {
				if( IsMatchRegexp( setting[1], "07(0|7)0" ) ) {
					compliant = "yes";
				}
				else {
					compliant = "no";
				}
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

