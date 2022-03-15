if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150270" );
	script_version( "2020-11-03T07:23:52+0000" );
	script_tag( name: "last_modification", value: "2020-11-03 07:23:52 +0000 (Tue, 03 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-06-17 09:34:21 +0000 (Wed, 17 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "GaussDB: Changing the Password of the Initial User" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "Policy/GaussDB/gaussdb_authentication_information.sc", "compliance_tests.sc", "gather-package-list.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://support.huawei.com/enterprise/en/doc/EDOC1100098622" );
	script_tag( name: "summary", value: "The initial user SYS is a system administrator and has all
system permissions. For database security, change the password of SYS as soon as possible after the
database is installed." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "Check password from VT 'GaussDB: Authentication Parameters' (OID: 1.3.6.1.4.1.25623.1.0.150259)";
title = "Changing the Password of the Initial User";
solution = "ALTER USER user_name IDENTIFIED BY newpassword REPLACE oldpassword;";
test_type = "DB_Check";
default = "Changeme_123";
if( !get_kb_item( "login/SSH/success" ) ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( !password = get_kb_item( "Policy/gaussdb/password" ) ){
		compliant = "incomplete";
		value = "error";
		comment = "Can not find password sys user";
	}
	else {
		if( get_kb_item( "Policy/gaussdb/user" ) != "SYS" ){
			compliant = "incomplete";
			value = "error";
			comment = "Scan user is not SYS.";
		}
		else {
			if( password == "Changeme_123" ){
				compliant = "no";
				value = "Changeme_123";
			}
			else {
				compliant = "yes";
				value = "Not 'Changeme_123'";
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

