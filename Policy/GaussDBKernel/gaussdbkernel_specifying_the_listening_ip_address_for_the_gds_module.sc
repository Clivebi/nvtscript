if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150423" );
	script_version( "2020-12-21T11:21:37+0000" );
	script_tag( name: "last_modification", value: "2020-12-21 11:21:37 +0000 (Mon, 21 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-20 10:52:10 +0000 (Fri, 20 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "GaussDB Kernel: Specifying the Listening IP Address for the GDS Module" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "gb_huawei_gaussdb_kernel_ssh_login_detect.sc" );
	script_mandatory_keys( "huawei/gaussdb_kernel/detected", "Compliance/Launch" );
	script_tag( name: "summary", value: "For the GDS module, you are advised to listen on the specified explicit IP
addresses on a network segment to listen on the connections to the network
Segment." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "Use system tools such as netstat or lsof to check whether the GDS module is
using the configured IP addresses for listening.";
title = "Specifying the Listening IP Address for the GDS Module";
solution = "Set startup parameters for the GDS module to specify IP addresses to be listened on:
'gds -p ip:port omm'";
default = "listening IP address";
test_type = "Manual Check";
compliant = "incomplete";
value = "Unknown";
comment = "Please check the value manually.";
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );
