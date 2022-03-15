if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150207" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-04-09 12:21:20 +0000 (Thu, 09 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "ZSQL: Number Of Password Changes Required Before the Current Password Can Be Reused" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "zsql_adm_profiles.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "entry", value: "3", id: 1 );
	script_xref( name: "URL", value: "https://support.huawei.com/enterprise/en/doc/EDOC1100098622" );
	script_tag( name: "summary", value: "Configure the number of password changes required before the
current password can be reused. The configuration prevents a password from being cracked due to
repeated use." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "SELECT RESOURCE_NAME, THRESHOLD FROM ADM_PROFILES WHERE RESOURCE_NAME='PASSWORD_REUSE_MAX';";
title = "Number Of Password Changes Required Before the Current Password Can Be Reused";
solution = "ALTER PROFILE profile_name LIMIT PASSWORD_REUSE_MAX 3;";
test_type = "SQL_Query";
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "Policy/zsql/adm_profiles/ssh/ERROR" ) ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( get_kb_item( "Policy/zsql/adm_profiles/ERROR" ) ){
		compliant = "incomplete";
		value = "error";
		comment = "Can not read table adm_profiles";
	}
	else {
		if( !value = get_kb_item( "Policy/zsql/adm_profiles/PASSWORD_REUSE_MAX/threshold" ) ){
			compliant = "incomplete";
			value = "error";
			comment = "Can not find value for PASSWORD_REUSE_MAX in table adm_profiles";
		}
		else {
			compliant = policy_setting_min_match( value: value, set_point: default );
		}
	}
}
policy_reporting( result: value, default: ">= " + default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

