if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150410" );
	script_version( "2020-12-21T11:21:37+0000" );
	script_tag( name: "last_modification", value: "2020-12-21 11:21:37 +0000 (Mon, 21 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-20 10:52:10 +0000 (Fri, 20 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "GaussDB Kernel: Restricting the Permission for the ${GAUSSHOME}/share Directory" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "gb_huawei_gaussdb_kernel_ssh_login_detect.sc" );
	script_mandatory_keys( "huawei/gaussdb_kernel/detected", "Compliance/Launch" );
	script_tag( name: "summary", value: "The ${GAUSSHOME} /share directory stores the shared components of GaussDB
Kernel. To prevent them from being tampered or damaged, the directory must be
protected and deny unauthorized user access." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "find ${GAUSSHOME}/share -prune -perm /g=w,o=w";
title = "Restricting the Permission for the ${GAUSSHOME}/share Directory";
solution = "chmod og-w ${GAUSSHOME}/share";
default = "None";
test_type = "Manual Check";
compliant = "incomplete";
value = "None";
comment = "Please check the value manually.";
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

