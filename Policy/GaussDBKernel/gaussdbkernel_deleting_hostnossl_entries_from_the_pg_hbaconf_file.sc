if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150426" );
	script_version( "2020-12-21T11:21:37+0000" );
	script_tag( name: "last_modification", value: "2020-12-21 11:21:37 +0000 (Mon, 21 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-20 10:52:10 +0000 (Fri, 20 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "GaussDB Kernel: Deleting hostnossl Entries from the pg_hba.conf File" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "gb_huawei_gaussdb_kernel_ssh_login_detect.sc" );
	script_mandatory_keys( "huawei/gaussdb_kernel/detected", "Compliance/Launch" );
	script_tag( name: "summary", value: "The connections specified by the hostnossl entries are not encrypted using SSL.
Considering security, you are advised to use the SSL connection.
SSL can be used for connections between the CN and external nodes but not for
connections between internal nodes." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "grep -P '^[^#]*hostnossl' ${GAUSSDATA}/pg_hba.conf";
title = "Deleting hostnossl Entries from the pg_hba.conf File";
solution = "Delete all the hostnossl entries from the pg_hba.conf file.";
default = "None";
test_type = "Manual Check";
compliant = "incomplete";
value = "None";
comment = "Please check the value manually.";
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

