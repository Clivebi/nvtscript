if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.115012" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-04-14 13:57:57 +0000 (Tue, 14 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "ZSQL: Check whether User PUBLIC has Object Permission" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "zsql_adm_tab_privs_query.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://support.huawei.com/enterprise/en/doc/EDOC1100098622" );
	script_tag( name: "summary", value: "Every user automatically belongs to user PUBLIC. For database
security, do not grant object permissions to user PUBLIC" );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "SELECT * FROM ADM_TAB_PRIVS WHERE GRANTEE='PUBLIC'";
title = "Check whether user PUBLIC has object permissions";
solution = "REVOKE ALL ON object_name FROM public";
test_type = "Manual Check";
default = "None";
if( get_kb_item( "Policy/zsql/zsql_adm_tab_privs/ssh/ERROR" ) ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host for ADM TAB PRIVS";
}
else {
	if( get_kb_item( "Policy/zsql/zsql_adm_tab_privs/ERROR" ) ){
		compliant = "incomplete";
		value = "error";
		comment = "Cannot read table ADM_TAB_PRIVS";
	}
	else {
		compliant = "incomplete";
		comment = "No automatic test possible. Please run 'SELECT * FROM ADM_TAB_PRIVS WHERE GRANTEE='PUBLIC';' ";
		comment += "and check for object permissions to public users.";
		value = "None";
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

