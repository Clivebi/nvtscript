if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150382" );
	script_version( "2020-11-17T10:41:45+0000" );
	script_tag( name: "last_modification", value: "2020-11-17 10:41:45 +0000 (Tue, 17 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-11 15:21:37 +0000 (Wed, 11 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "openGauss: Configure an Audit Priority Policy" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gb_huawei_opengauss_ssh_login_detect.sc", "compliance_tests.sc", "opengauss_authentication_information.sc" );
	script_mandatory_keys( "huawei/opengauss/detected", "Compliance/Launch" );
	script_xref( name: "URL", value: "https://opengauss.org" );
	script_tag( name: "summary", value: "Configures the policy for determining whether audit logs are preferentially stored
by space or time." );
	exit( 0 );
}
require("policy_functions.inc.sc");
require("ssh_func.inc.sc");
cmd = "SELECT name,setting FROM pg_settings WHERE name = 'audit_resource_policy';";
title = "Configure an Audit Priority Policy";
solution = "gs_guc reload -N all -I all -c 'audit_resource_policy = on'";
default = "on";
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
			setting = eregmatch( string: value, pattern: "audit_resource_policy\\s+\\|\\s+(.+)" );
			if( !setting[1] ){
				compliant = "incomplete";
				comment = "Can not determine setting.";
			}
			else {
				compliant = policy_setting_exact_match( value: setting[1], set_point: default );
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );
