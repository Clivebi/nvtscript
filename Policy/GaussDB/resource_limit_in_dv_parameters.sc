if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150213" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-04-09 13:12:22 +0000 (Thu, 09 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "ZSQL: Resource Limit of a Single User" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "zsql_dv_parameters.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "radio", value: "TRUE;FALSE", id: 1 );
	script_xref( name: "URL", value: "https://support.huawei.com/enterprise/en/doc/EDOC1100098622" );
	script_tag( name: "summary", value: "Configure the resource limit to enable the maximum number of
connections of a single user as defined in ADM_PROFILES table." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "SELECT NAME,VALUE FROM DV_PARAMETERS WHERE NAME='RESOURCE_LIMIT'";
title = "Resource Limit of a Single User";
solution = "ALTER SYSTEM SET RESOURCE_LIMIT = TRUE;";
test_type = "SQL_Query";
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "Policy/zsql/dv_parameters/ssh/ERROR" ) ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( get_kb_item( "Policy/zsql/dv_parameters/ERROR" ) ){
		compliant = "incomplete";
		value = "error";
		comment = "Can not read table dv_parameters";
	}
	else {
		if( !value = get_kb_item( "Policy/zsql/dv_parameters/RESOURCE_LIMIT/value" ) ){
			compliant = "incomplete";
			value = "error";
			comment = "Can not find value for RESOURCE_LIMIT in table dv_parameters";
		}
		else {
			compliant = policy_setting_exact_match( value: value, set_point: default );
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );
