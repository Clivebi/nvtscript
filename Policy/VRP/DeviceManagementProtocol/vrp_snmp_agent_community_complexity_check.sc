if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150249" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-14 07:32:07 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: SNMP agent complexity-check" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_current_configuration_snmp.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "If SNMPv1 and SNMPv2 are used, the community complexity check
  function must be enabled." );
	exit( 0 );
}
require("policy_functions.inc.sc");
port = get_kb_item( "huawei/vrp/ssh-login/port" );
model = get_kb_item( "huawei/vrp/ssh-login/" + port + "/model" );
major_version = get_kb_item( "huawei/vrp/ssh-login/major_version" );
if( IsMatchRegexp( major_version, "^8" ) ) {
	cmd = "display snmp-agent sys-info version; display current-configuration | include snmp";
}
else {
	cmd = "display current-configuration | include snmp";
}
title = "Configure community name complexity check";
solution = "Run the undo snmp-agent community complexity-check disable command to enable the
complexity check function for community names.";
test_type = "SSH_Cmd";
default = "Enable";
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
		if( IsMatchRegexp( model, "^AR" ) && IsMatchRegexp( major_version, "^5" ) ){
			exit( 0 );
		}
		else {
			if( get_kb_item( "Policy/vrp/ssh/ERROR" ) ){
				value = "Error";
				compliant = "incomplete";
				comment = "No SSH connection to VRP device.";
			}
			else {
				if( get_kb_item( "Policy/vrp/current_configuration/snmp/empty" ) ){
					value = "SNMP disabled";
					compliant = "yes";
					comment = "The command '" + cmd + "' did not return anything";
				}
				else {
					if( !sys_info_version = get_kb_item( "Policy/vrp/snmp_agent_version" ) ){
						value = "Error";
						compliant = "incomplete";
						comment = "Can not determine the snmp-agent sys-info version.";
					}
					else {
						if( !IsMatchRegexp( sys_info_version, "(SNMPv1|SNMPv2c|SNMPv1|SNMPv2|v1|v2c|all)" ) ){
							value = "SNMP agent version: " + sys_info_version;
							compliant = "yes";
							comment = "SNMP agent version not matching SNMPv1, SNMPv2c, SNMPv1, SNMPv2, v1, v2c or all";
						}
						else {
							snmp = get_kb_item( "Policy/vrp/current_configuration/snmp" );
							if( IsMatchRegexp( snmp, "snmp-agent\\s+community\\s+complexity-check\\s+disable" ) && !IsMatchRegexp( snmp, "undo\\s+snmp-agent\\s+community\\s+complexity-check\\s+disable" ) ){
								value = "Disable";
								compliant = "no";
								comment = "SNMP v1 or v2 enabled, complexity check for community names disabled.";
							}
							else {
								value = "Enable";
								compliant = "yes";
								comment = "SNMP v1 or v2 enabled, complexity check for community names enabled.";
							}
						}
					}
				}
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

