if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.115019" );
	script_version( "2020-07-29T07:27:10+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 07:27:10 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-04-29 13:31:58 +0000 (Wed, 29 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Strictly define variable user PATH variable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_tag( name: "summary", value: "The requirement aims to prevent system commands from being
replaced by malicious commands, ensuring that system commands can be executed securely." );
	exit( 0 );
}
require("policy_functions.inc.sc");
title = "Strictly Define User PATH variable";
cmd = "None";
solution = "Strictly Define User PATH variable";
test_type = "Manual Check";
default = "None";
value = "None";
compliant = "Yes";
comment = "No automatic test possible. Check the PATH variable for any account.";
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
exit( 0 );

