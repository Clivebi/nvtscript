if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150282" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-13 06:10:09 +0000 (Mon, 13 Jul 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Deploying BGP4+ Authentication and GTSM" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_current_configuration_configuration_bgp.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "BGP4+ MD5 authentication and GTSM are deployed to prevent
attackers from attempting to use the control plane protocol to destroy entries on which
forwarding depends, such as routes." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
require("list_array_func.inc.sc");
port = get_kb_item( "huawei/vrp/ssh-login/port" );
model = get_kb_item( "huawei/vrp/ssh-login/" + port + "/model" );
major_version = get_kb_item( "huawei/vrp/ssh-login/major_version" );
cmd = "display current-configuration configuration bgp";
title = "Deploying BGP4+ Authentication and GTSM";
solution = "Deploy BGP4+ MD5 authentication and GTSM, and add the password and valid-ttl-hops
configurations.";
test_type = "SSH_Cmd";
default = "All peers configured with password and valid-ttl-hops or ebgp-max-hop";
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
				if( get_kb_item( "Policy/vrp/current_configuration/configuration/bgp/ERROR" ) ){
					value = "Error";
					compliant = "incomplete";
					comment = "Can not determine the current bgp configuration.";
				}
				else {
					current_bgp_configuration = get_kb_item( "Policy/vrp/current_configuration/configuration/bgp" );
					peer_ipv6 = make_list();
					for line in split( buffer: current_bgp_configuration, keep: FALSE ) {
						ipv6_address = eregmatch( string: line, pattern: "peer\\s+([0-9,A-Z,a-z,:]+)\\s+" );
						if(ipv6_address){
							peer_ipv6 = make_list( peer_ipv6,
								 ipv6_address[1] );
						}
					}
					if( max_index( peer_ipv6 ) == 0 ){
						value = "None";
						compliant = "yes";
						comment = "No peer exists";
					}
					else {
						peer_ipv6 = nasl_make_list_unique( peer_ipv6 );
						for ip in peer_ipv6 {
							if(!ereg( string: current_bgp_configuration, multiline: TRUE, pattern: "peer " + ip + " password" ) || !ereg( string: current_bgp_configuration, multiline: TRUE, pattern: "peer " + ip + " (valid-ttl-hops|ebgp-max-hop)" )){
								compliant = "no";
								value = "Not all peer have password and valid-ttl-hops or ebgp-max-hop configured";
								comment += ip + " ";
							}
						}
						if(!compliant){
							compliant = "yes";
							value = "All peers configured with password and valid-ttl-hops or ebgp-max-hop";
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
