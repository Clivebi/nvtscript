if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150120" );
	script_version( "2021-05-14T14:03:39+0000" );
	script_tag( name: "last_modification", value: "2021-05-14 14:03:39 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "creation_date", value: "2020-02-03 15:01:35 +0100 (Mon, 03 Feb 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: /etc/issue chown" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_etc_issue.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "entry", value: "root:root", id: 1 );
	script_xref( name: "URL", value: "http://man7.org/linux/man-pages/man5/issue.5.html" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 1.7.1.5 Ensure permissions on /etc/issue are configured (Scored)" );
	script_xref( name: "Policy", value: "CIS CentOS Linux 8 Benchmark v1.0.0: 1.8.1.5 Ensure permissions on /etc/issue are configured (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 5.1 Establish Secure Configurations" );
	script_tag( name: "summary", value: "/etc/issue is a text file which contains a message or system
identification to be printed before the login prompt." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "stat /etc/issue";
title = "chown /etc/issue";
solution = "chown USER:GROUP /etc/issue";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "Policy/linux//etc/issue/stat/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Could not get information about /etc/issue";
}
else {
	stat = get_kb_item( "Policy/linux//etc/issue/stat" );
	uid = policy_chown_get_uid( stat: stat );
	gid = policy_chown_get_gid( stat: stat );
	value = uid + ":" + gid;
	compliant = policy_setting_exact_match( value: value, set_point: default );
	comment = "";
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

