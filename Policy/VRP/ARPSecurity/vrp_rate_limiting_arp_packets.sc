if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150258" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-15 12:08:01 +0000 (Fri, 15 May 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Configuring ARP Packet Rate Limiting" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_current_configuration.sc", "vrp_display_arp_speed_limit.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "After the rate limit for ARP packets is configured, the device counts
the number of ARP packets. If the number of ARP packets exceeds the configured threshold
within a certain period, the device does not process the excess ARP packets." );
	exit( 0 );
}
require("policy_functions.inc.sc");
title = "Configuring ARP Packet Rate Limiting";
solution = "By default, the rate limit based on the source IP address is 30. In an insecure
environment, you can reduce the rate limit to reduce the rate of processing ARP packets.";
test_type = "SSH_Cmd";
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
		if( !major_version = get_kb_item( "huawei/vrp/ssh-login/major_version" ) ){
			value = "Error";
			compliant = "incomplete";
			comment = "Can not determine version of device.";
		}
		else {
			if( IsMatchRegexp( major_version, "^8" ) ){
				cmd = "display arp speed-limit";
				default_sourceip = "100";
				default_destinationip = "500";
				default = "Source-ip >= " + default_sourceip + ", Destination-ip >= " + default_destinationip;
				if( get_kb_item( "Policy/vrp/arp/speedlimit/ERROR" ) ){
					value = "Error";
					compliant = "incomplete";
					comment = "Can not determine the current arp speed-limit configuration.";
				}
				else {
					slots = get_kb_list( "Policy/vrp/arp/speedlimit/slots" );
					for slot in slots {
						sourceip = get_kb_item( "Policy/vrp/arp/speedlimit/" + slot + "/sourceip" );
						destinationip = get_kb_item( "Policy/vrp/arp/speedlimit/" + slot + "/destinationip" );
						if(policy_setting_min_match( value: sourceip, set_point: default_sourceip ) == "no" || policy_setting_min_match( value: destinationip, set_point: default_destinationip ) == "no"){
							value = "Source-ip not >= " + default_sourceip + " or Destination-ip not >= " + default_destinationip;
							compliant = "no";
						}
					}
					if(!value){
						value = "Source-ip >= " + default_sourceip + ", Destination-ip >= " + default_destinationip;
						compliant = "yes";
					}
				}
			}
			else {
				default = "30";
				cmd = "display current-configuration";
				if( get_kb_item( "Policy/vrp/current_configuration/ERROR" ) ){
					value = "Error";
					compliant = "incomplete";
					comment = "Can not determine the current arp configuration.";
				}
				else {
					vrp_configuration = get_kb_item( "Policy/vrp/current_configuration" );
					arp_max = eregmatch( string: vrp_configuration, pattern: "arp\\s+speed-limit\\s+source-ip\\s+[0-9.\\s]*maximum\\s+([0-9]+)" );
					if( arp_max ) {
						value = arp_max[1];
					}
					else {
						value = "None";
					}
					compliant = policy_setting_min_match( value: value, set_point: default );
				}
				default = ">= " + default;
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

