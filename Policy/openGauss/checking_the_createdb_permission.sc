if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150359" );
	script_version( "2020-11-12T15:07:01+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 15:07:01 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-11 15:21:37 +0000 (Wed, 11 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "openGauss: Checking the CREATEDB Permission" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gb_huawei_opengauss_ssh_login_detect.sc", "compliance_tests.sc", "opengauss_authentication_information.sc" );
	script_mandatory_keys( "huawei/opengauss/detected", "Compliance/Launch" );
	script_xref( name: "URL", value: "https://opengauss.org" );
	script_tag( name: "summary", value: "Only the role with the CREATEDB permission can create databases. Such a role
can also create and define database users. To avoid arbitrary database creation,
delete roles that do not require the CREATEDB permission." );
	exit( 0 );
}
require("policy_functions.inc.sc");
require("ssh_func.inc.sc");
cmd = "SELECT rolname FROM pg_roles WHERE rolcreatedb=true AND rolsuper=false;";
title = "Checking the CREATEDB Permission";
solution = "DROP ROLE <ROLE_NAME> ;";
default = "N/A";
test_type = "SQL_Query";
if( !get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection() ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( !value = policy_gsql_cmd( socket: sock, query: cmd ) ){
		compliant = "yes";
		value = "N/A";
	}
	else {
		if( IsMatchRegexp( value, "failed to connect" ) ){
			compliant = "incomplete";
			value = "error";
			comment = "No connection to database";
		}
		else {
			compliant = "no";
			value = ereg_replace( string: chomp( value ), pattern: "^\\s+", replace: "" );
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, query: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

