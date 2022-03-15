if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150237" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-14 07:32:07 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: SSH Server Version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_ssh_server_status.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "The SSH version 1.0 is considered as unsecure and thus should not be used." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "display ssh server status";
title = "SSH Server Version";
solution = "Run the undo ssh server compatible ssh1x enable command to enable SSHv2.";
test_type = "SSH_Cmd";
default = "2.0";
if( get_kb_item( "Policy/vrp/installed/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No VRP device detected.";
}
else {
	if( get_kb_item( "Policy/vrp/ssh/ERROR" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "No SSH connection to VRP device.";
	}
	else {
		if( get_kb_item( "Policy/vrp/current_configuration/ssh_status/ERROR" ) ){
			value = "Error";
			compliant = "incomplete";
			comment = "Can not determine the current SSH server status.";
		}
		else {
			if( !value = get_kb_item( "Policy/vrp/current_configuration/ssh_status/sshversion" ) ){
				value = "Error";
				compliant = "incomplete";
				comment = "Can not determine the SSH version.";
			}
			else {
				compliant = policy_setting_min_match( value: value, set_point: default );
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

