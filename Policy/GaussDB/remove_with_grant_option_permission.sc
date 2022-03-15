if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.115002" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-03-24 15:29:57 +0000 (Tue, 24 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "ZSQL: Check for users with WITH GRANT OPTION permission" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "zsql_adm_tab_privs_query.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://support.huawei.com/enterprise/en/doc/EDOC1100098622" );
	script_tag( name: "summary", value: "Searches for users with the WITH GRANT OPTION permission and
checks whether they are autorized to have it. Users with this permission can grant object
permissions to other users. For database security, specify this permission attribute only when
absolutely necessary." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "SELECT * FROM ADM_TAB_PRIVS WHERE GRANTABLE = 'YES'";
title = "List users with WITH GRANT OPTION permission";
solution = "1) REVOKE ALL ON object_name FROM user_name;
 2) GRANT privilege_name ON object_name TO user_name;
  without WITH GRANT OPTION specified ";
test_type = "SQL_Query";
default = "None";
if( get_kb_item( "Policy/zsql/zsql_adm_tab_privs/ssh/ERROR" ) ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( get_kb_item( "Policy/zsql/zsql_adm_tab_privs/ERROR" ) ){
		compliant = "incomplete";
		value = "error";
		comment = "Cannot read table ADM_TAB_PRIVS";
	}
	else {
		if( !grantee_list = get_kb_list( "Policy/zsql/zsql_adm_tab_privs/*/*/*/GRANTABLE" ) ){
			compliant = "incomplete";
			value = "error";
			comment = "Cannot parse table ADM_TAB_PRIVS";
		}
		else {
			for key in keys( grantee_list ) {
				if(grantee_list[key] == "YES"){
					items = split( buffer: key, sep: "/", keep: FALSE );
					value += "," + items[3] + ":" + items[4];
				}
			}
			if( value ){
				value = str_replace( string: value, find: ",", replace: "", count: 1 );
			}
			else {
				value = "None";
			}
			compliant = policy_setting_exact_match( value: value, set_point: default );
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

