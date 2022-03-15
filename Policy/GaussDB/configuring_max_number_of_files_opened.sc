if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.115014" );
	script_version( "2020-07-29T09:05:18+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:05:18 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-04-29 12:04:58 +0000 (Wed, 29 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "GaussDB: Configure the Maximum Number of Files that Can Be Opened in Processes" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://support.huawei.com/enterprise/en/doc/EDOC1100098622" );
	script_tag( name: "summary", value: "If the maxmimum number of files that can be opened in processes
is too small, SQL operations will fail once the maximum number is exceeded." );
	exit( 0 );
}
require("policy_functions.inc.sc");
title = "Configure the Maximum Numbers of Files That Can Be Opened in Processes";
cmd = "None";
solution = "None";
test_type = "SQL_Query";
default = "None";
value = "None";
compliant = "incomplete";
comment = "";
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
exit( 0 );

