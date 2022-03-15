if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150192" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-04-02 18:00:36 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "GaussDB: Access permissions to ${GSDB_DATA}/cfg/zengine.ini" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_gsdb_data_permissions.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "entry", value: "600", id: 1 );
	script_xref( name: "URL", value: "https://support.huawei.com/enterprise/en/doc/EDOC1100098622" );
	script_tag( name: "summary", value: "The zengine.ini file stores database connection configuration." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
cmd = "stat ${GSDB_DATA}/cfg/zengine.ini";
title = "Access permissions to ${GSDB_DATA}/cfg/zengine.ini";
solution = "chmod PERMISSION ${GSDB_DATA}/cfg/zengine.ini";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "Policy/linux/gaussdb/${GSDB_DATA}/ssh/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host possible";
}
else {
	if( get_kb_item( "Policy/linux/${GSDB_DATA}/cfg/zengine.ini/stat/ERROR" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Could not get information about ${GSDB_DATA}/cfg/zengine.ini";
	}
	else {
		stat = get_kb_item( "Policy/linux/${GSDB_DATA}/cfg/zengine.ini/stat" );
		value = policy_get_access_permissions( stat: stat );
		compliant = policy_access_permissions_match_or_stricter( value: value, set_point: default );
		grep_file = egrep( string: stat, pattern: "File:" );
		file = eregmatch( string: grep_file, pattern: "File:[^/]+([a-z,A-Z,_,/,-,.,0-9]*)" );
		comment = "File: " + file[1];
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

