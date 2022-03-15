if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150253" );
	script_version( "2021-07-31T11:19:19+0000" );
	script_tag( name: "last_modification", value: "2021-07-31 11:19:19 +0000 (Sat, 31 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-05-14 13:56:29 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Validity check of ARP packets" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "vrp_current_configuration.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "After the validity check of ARP packets is configured, the device
checks the consistency between the source and destination MAC addresses in the Ethernet packet
header and those in the Data field of the ARP packet." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "None";
title = "Validity check of ARP packets";
solution = "Configure ARP packet validity check.";
test_type = "Manual Check";
default = "None";
comment = "No automatic test possible. Run 'display current-configuration interface INTERFACE' to check
if arp validate command is configured on the ARP interface.";
compliant = "incomplete";
if(get_kb_item( "Policy/vrp/installed/ERROR" )){
	value = "Error";
	compliant = "incomplete";
	comment = "No VRP device detected.";
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

