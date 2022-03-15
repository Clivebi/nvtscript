if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150373" );
	script_version( "2020-12-21T11:24:45+0000" );
	script_tag( name: "last_modification", value: "2020-12-21 11:24:45 +0000 (Mon, 21 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-11 15:21:37 +0000 (Wed, 11 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "openGauss: Controlling the Permission to Execute the SECURITY INVOKER Function" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gb_huawei_opengauss_ssh_login_detect.sc", "compliance_tests.sc", "opengauss_authentication_information.sc" );
	script_mandatory_keys( "huawei/opengauss/detected", "Compliance/Launch" );
	script_xref( name: "URL", value: "https://opengauss.org" );
	script_tag( name: "summary", value: "The SECURITY INVOKER function is executed with the permissions of the invoker.
Before invoking such a function not created by yourself, check the function
content to prevent the function creator from performing unauthorized operations
with your permissions." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "None";
title = "Controlling the Permission to Execute the SECURITY INVOKER Function";
solution = "None";
default = "N/A";
test_type = "Manual Check";
value = "None";
compliant = "incomplete";
comment = "Please check the value manually.";
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

