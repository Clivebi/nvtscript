if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150440" );
	script_version( "2020-11-20T12:35:19+0000" );
	script_tag( name: "last_modification", value: "2020-11-20 12:35:19 +0000 (Fri, 20 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-20 10:52:10 +0000 (Fri, 20 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "GaussDB Kernel: Enabling Unified Audit" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "gb_huawei_gaussdb_kernel_ssh_login_detect.sc", "gaussdbkernel_authentication_information.sc" );
	script_mandatory_keys( "huawei/gaussdb_kernel/detected", "Compliance/Launch" );
	script_tag( name: "summary", value: "Unified audit allows you to bind resource labels and output audit logs based on
customized audit policies, improving the efficiency of database monitoring by
administrators. Therefore, you are advised to enable enable_security_policy." );
	exit( 0 );
}
require("policy_functions.inc.sc");
require("ssh_func.inc.sc");
cmd = "SELECT name,setting FROM pg_settings WHERE name = 'enable_security_policy';";
title = "Enabling Unified Audit";
solution = "gs_guc reload -Z coordinator -N all -I all -c 'enable_security_policy=on'";
default = "on";
test_type = "SQL_Query";
if( !get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection() ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( !value = policy_gsql_cmd( socket: sock, query: cmd, db_type: "gaussdbkernel" ) ){
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
			setting = eregmatch( string: value, pattern: "enable_security_policy\\s+\\|\\s+(.+)" );
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

