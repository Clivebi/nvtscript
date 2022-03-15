if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150238" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-14 07:49:21 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: VTY SSH Access Mode" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_current_configuration_user_interface.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "If the user access mode is set to a non-SSH mode, it is not secure
enough." );
	exit( 0 );
}
require("policy_functions.inc.sc");
port = get_kb_item( "huawei/vrp/ssh-login/port" );
model = get_kb_item( "huawei/vrp/ssh-login/" + port + "/model" );
major_version = get_kb_item( "huawei/vrp/ssh-login/major_version" );
cmd = "display current-configuration configuration user-interface";
title = "SSH Access Mode";
solution = "Configure the SSH access mode.";
test_type = "SSH_Cmd";
default = "SSH";
if( get_kb_item( "Policy/vrp/installed/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No VRP device detected.";
}
else {
	if( !model || !major_version ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not determine model or version of VRP device.";
	}
	else {
		if( IsMatchRegexp( model, "^S" ) && IsMatchRegexp( major_version, "^5" ) ){
			exit( 0 );
		}
		else {
			if( get_kb_item( "Policy/vrp/ssh/ERROR" ) ){
				value = "Error";
				compliant = "incomplete";
				comment = "No SSH connection to VRP device.";
			}
			else {
				if( get_kb_item( "Policy/vrp/current_configuration/user_interface/ERROR" ) ){
					value = "Error";
					compliant = "incomplete";
					comment = "Can not determine the current user-interface configuration.";
				}
				else {
					user_interface = get_kb_item( "Policy/vrp/current_configuration/user_interface" );
					for interface in split( buffer: user_interface, sep: "user-interface", keep: TRUE ) {
						if(IsMatchRegexp( interface, "^\\s*vty" )){
							if(!IsMatchRegexp( interface, "protocol\\s+inbound\\s+ssh" )){
								value = "Not SSH";
								compliant = "no";
								comment = "Not all vty user-interfaces have set 'protocol inbound ssh'";
							}
						}
					}
					if(!value){
						value = "SSH";
						comment = "All vty user-interfaces have set 'protocol inbound ssh'";
					}
					compliant = policy_setting_exact_match( value: tolower( value ), set_point: tolower( default ) );
				}
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

