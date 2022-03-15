if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150269" );
	script_version( "2020-11-03T07:19:19+0000" );
	script_tag( name: "last_modification", value: "2020-11-03 07:19:19 +0000 (Tue, 03 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-06-17 08:00:52 +0000 (Wed, 17 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "ZSQL: Configure User Whitelist" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "zsql_dv_hba.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://support.huawei.com/enterprise/en/doc/EDOC1100098622" );
	script_tag( name: "summary", value: "To prevent account disclosure, you can configure a whitelist to
specify users with high-level permissions and client IP addresses allowed for database connections." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "SELECT * FROM DV_HBA;";
title = "Configure User Whitelist";
solution = "Add an HBA entry (TYPE, USER, and ADDRESS) to the zhba.conf file. Run 'ALTER SYSTEM RELOAD HBA CONFIG;'";
test_type = "SQL_Query";
default = "not empty";
if( get_kb_item( "Policy/zsql/zsql_dv_hba/ssh/ERROR" ) ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( get_kb_item( "Policy/zsql/zsql_dv_hba/ERROR" ) ){
		compliant = "incomplete";
		value = "error";
		comment = "Can not read table DV_HBA";
	}
	else {
		if( !value = get_kb_list( "Policy/zsql/zsql_dv_hba/types" ) ){
			compliant = "no";
			value = "Empty";
			comment = "Can not find any entry in DV_HBA";
		}
		else {
			compliant = "yes";
			value = "not empty";
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

