if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150464" );
	script_version( "2020-12-23T08:48:08+0000" );
	script_tag( name: "last_modification", value: "2020-12-23 08:48:08 +0000 (Wed, 23 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-20 10:52:10 +0000 (Fri, 20 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "GaussDB Kernel: Controlling the Permission to Execute the SECURITY DEFINER Function" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "gb_huawei_gaussdb_kernel_ssh_login_detect.sc", "gaussdbkernel_authentication_information.sc" );
	script_mandatory_keys( "huawei/gaussdb_kernel/detected", "Compliance/Launch" );
	script_tag( name: "summary", value: "Because the SECURITY DEFINER function is executed with the privileges of the
user that created it, ensure that this function is not misused. For security purposes,
set search_path to exclude any schemas writable by untrusted users. This prevents
malicious users from creating objects that mask objects used by the function." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "show search_path; SELECT CAST(has_function_privilege('public', 'function_name()', 'EXECUTE') AS TEXT);";
title = "Controlling the Permission to Execute the SECURITY DEFINER Function";
solution = "SET search_path = VALUE;";
default = "N/A";
test_type = "Manual Check";
compliant = "incomplete";
value = "None";
comment = "Please check the value manually.";
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

