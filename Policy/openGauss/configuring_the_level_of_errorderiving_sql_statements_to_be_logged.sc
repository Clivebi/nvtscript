if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150396" );
	script_version( "2020-11-17T12:21:54+0000" );
	script_tag( name: "last_modification", value: "2020-11-17 12:21:54 +0000 (Tue, 17 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-11 15:21:37 +0000 (Wed, 11 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "openGauss: Configuring the Level of Error-Deriving SQL Statements to Be Logged" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gb_huawei_opengauss_ssh_login_detect.sc", "compliance_tests.sc", "opengauss_authentication_information.sc" );
	script_mandatory_keys( "huawei/opengauss/detected", "Compliance/Launch" );
	script_xref( name: "URL", value: "https://opengauss.org" );
	script_tag( name: "summary", value: "The log_min_error_statement parameter specifies which level of SQL statements
that cause an error will be recorded into server logs. SQL statements whose levels
are higher than or equal to the configured level will be recorded into server logs.
The valid values include DEBUG5, DEBUG4, DEBUG3, DEBUG2, DEBUG1, INFO,
NOTICE, WARNING, ERROR, LOG, FATAL, and PANIC. It must be ERROR at least.
Some SQL statements contain personal information. If SQL statements that cause
errors do not need to be recorded, set this parameter to PANIC." );
	exit( 0 );
}
require("policy_functions.inc.sc");
require("ssh_func.inc.sc");
cmd = "SELECT name,setting FROM pg_settings WHERE name='log_min_error_statement';";
title = "Configuring the Level of Error-Deriving SQL Statements to Be Logged";
solution = "Set log_min_error_statement to error in the postgresql.conf file and restart the database.";
default = "ERROR, FATAL, or PANIC";
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
			setting = eregmatch( string: value, pattern: "log_min_error_statement\\s+\\|\\s+(.+)" );
			if( !setting[1] ){
				compliant = "incomplete";
				comment = "Can not determine setting.";
			}
			else {
				if( IsMatchRegexp( setting[1], "(ERROR|FATAL|PANIC)" ) ){
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

