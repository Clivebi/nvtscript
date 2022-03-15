if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.115010" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-04-07 14:00:05 +0000 (Tue, 07 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "ZSQL: Check for users with CREATE DATABASE permission" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "zsql_db_user_sys_priv_query.sc", "zsql_role_sys_privs.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://support.huawei.com/enterprise/en/doc/EDOC1100098622" );
	script_tag( name: "summary", value: "Searches for users and roles with CREATE DATABASE permission and checks whether they are authorized to have it. A user with the CREATE DATABASE permission can creata a database. If this permission is no longer necessary, revoke it." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "SELECT USERNAME, PRIVILEGE FROM DB_USER_SYS_PRIVS WHERE USERNAME = 'user_name' AND PRIVILEGE = 'CREATE DATABASE'";
title = "Check for users with CREATE DATABASE permission";
solution = "1) REVOKE CREATE DATABASE FROM user_name;
2) REVOKE CREATE DATABASE FROM role_name;";
test_type = "SQL_Query";
default = "User:Sys, Roles:DBA";
user_list = make_list();
role_list = make_list();
if( get_kb_item( "Policy/zsql/zsql_db_user_sys_privs/ssh/ERROR" ) || get_kb_item( "Policy/zsql/zsql_role_sys_privs/ssh/ERROR" ) ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( get_kb_item( "Policy/zsql/zsql_db_user_sys_privs/ERROR" ) || get_kb_item( "Policy/zsql/zsql_role_sys_privs/ERROR" ) ){
		compliant = "incomplete";
		value = "error";
		comment = "Cannot read table DB_USER_SYS_PRIVS or ROLE_SYS_PRIVS";
	}
	else {
		if( ( !grantee_list = get_kb_list( "Policy/zsql/zsql_db_user_sys_privs/*" ) ) || ( !role_sys_privs_list = get_kb_list( "Policy/zsql/zsql_role_sys_privs/*" ) ) ){
			compliant = "incomplete";
			value = "error";
			comment = "Cannot parse table DB_USER_SYS_PRIVS or DB_USER_SYS_PRIVS";
		}
		else {
			for key1 in keys( grantee_list ) {
				if(IsMatchRegexp( key1, "CREATE DATABASE" )){
					user = eregmatch( string: key1, pattern: "Policy/zsql/zsql_db_user_sys_privs/([^/]+)/*" );
					if(user){
						user_list = make_list( user_list,
							 user[1] );
					}
				}
			}
			for key2 in keys( role_sys_privs_list ) {
				if(IsMatchRegexp( key2, "CREATE DATABASE" )){
					role = eregmatch( string: key2, pattern: "Policy/zsql/zsql_role_sys_privs/([^/]+)/*" );
					if(role){
						role_list = make_list( role_list,
							 role[1] );
					}
				}
			}
			value = "User:" + policy_build_string_from_list( list: user_list, sep: "," );
			value += ", Roles:" + policy_build_string_from_list( list: role_list, sep: "," );
			compliant = policy_settings_lists_match( value: toupper( value ), set_points: toupper( default ), sep: "," );
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

