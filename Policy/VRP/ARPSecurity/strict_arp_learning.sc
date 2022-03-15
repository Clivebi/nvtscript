if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150254" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-15 11:05:34 +0000 (Fri, 15 May 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Configuring Strict ARP Learning" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_current_configuration.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "Strict ARP learning is configured so that the device learns only the
ARP reply packets in response to the ARP request packets sent by itself, and does not learn the
ARP request packets sent by other devices to the router. In this manner, the device can defend
against most ARP request packet attacks." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "display current-configuration";
title = "Configuring Strict ARP Learning";
solution = "Enable strict ARP learning on insecure ports.";
test_type = "SSH_Cmd";
default = "Enable";
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
		if( get_kb_item( "Policy/vrp/current_configuration/ERROR" ) ){
			value = "Error";
			compliant = "incomplete";
			comment = "Can not determine the current configuration.";
		}
		else {
			current_configuration = get_kb_item( "Policy/vrp/current_configuration" );
			if( IsMatchRegexp( current_configuration, "arp\\s+learning\\s+strict" ) ){
				value = "Enable";
			}
			else {
				value = "Disable";
			}
			compliant = policy_setting_exact_match( value: value, set_point: default );
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

