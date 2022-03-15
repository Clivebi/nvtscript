if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150256" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-15 11:05:34 +0000 (Fri, 15 May 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Configuring Rate Limit for ARP Miss Messages" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_display_arpmiss_speedlimit_sourceip.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "After rate limit for ARP Miss messages is configured, the device
counts the number of ARP Miss messages. If the number of ARP Miss messages exceeds the
threshold, the device does not process the excess ARP Miss messages." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "display arp-miss speed-limit source-ip";
title = "Configuring Rate Limit for ARP Miss Messages";
solution = "By default, ARP Miss message rate limiting based on source IP addresses is enabled, and
30 packets are processed per second. In an insecure environment, you can decrease the rate limit.";
test_type = "SSH_Cmd";
default = "30";
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
		if( get_kb_item( "Policy/vrp/arpmiss/speedlimit/sourceip/ERROR" ) ){
			value = "Error";
			compliant = "incomplete";
			comment = "Can not determine the current configuration.";
		}
		else {
			arpmiss_speedlimit_sourceip = get_kb_item( "Policy/vrp/arpmiss/speedlimit/sourceip" );
			arpmiss_value = eregmatch( string: arpmiss_speedlimit_sourceip, pattern: "ARP-miss\\s+([0-9]+)" );
			if( arpmiss_value ) {
				value = arpmiss_value[1];
			}
			else {
				value = "None";
			}
			compliant = policy_setting_min_match( value: value, set_point: default );
		}
	}
}
policy_reporting( result: value, default: ">= " + default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: ">= " + default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

