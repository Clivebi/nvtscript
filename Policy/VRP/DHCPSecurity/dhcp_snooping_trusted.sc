if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150295" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-14 07:39:50 +0000 (Tue, 14 Jul 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Configuring a Trusted Interface to Prevent Bogus DHCP Server Attacks" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_current_configuration.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "To prevent bogus DHCP server attacks, you can configure the
trusted and untrusted modes for DHCP snooping." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "display current-configuration";
title = "Configuring a Trusted Interface to Prevent Bogus DHCP Server Attacks";
solution = "To prevent attacks from bogus DHCP servers, configure DHCP snooping.
Configure the network-side interface as the trusted interface and the user-side interface as the
untrusted interface. All DHCP reply packets received from the untrusted interface are
discarded.";
test_type = "SSH_Cmd";
default = "Enabled";
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
			if( IsMatchRegexp( current_configuration, "dhcp\\s+snooping\\s+trusted" ) ) {
				value = "Enabled";
			}
			else {
				value = "Disabled";
			}
			compliant = policy_setting_exact_match( value: value, set_point: default );
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

