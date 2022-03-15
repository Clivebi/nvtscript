if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109737" );
	script_version( "2021-05-14T14:03:39+0000" );
	script_tag( name: "last_modification", value: "2021-05-14 14:03:39 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "creation_date", value: "2019-01-16 08:27:48 +0100 (Wed, 16 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Address space layout randomization (ASLR) status" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_and_parse_sysctl.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Status", type: "radio", value: "Enabled;Disabled", id: 1 );
	script_xref( name: "URL", value: "https://linux-audit.com/linux-aslr-and-kernelrandomize_va_space-setting/" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 1.5.3 Ensure address space layout randomization (ASLR) is enabled (Scored)" );
	script_xref( name: "Policy", value: "CIS CentOS Linux 8 Benchmark v1.0.0: 1.6.2 Ensure address space layout randomization (ASLR) is enabled (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 8.3 Enable Operating System Anti-Exploitation Features/ Deploy Anti-Exploit Technologies" );
	script_tag( name: "summary", value: "Address space layout randomization (ASLR) is an exploit
mitigation technique which randomly arranges the address space of key data areas of a process." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "sysctl kernel.randomize_va_space";
title = "Address space layout randomization (ASLR) status";
solution = "sysctl -w kernel.randomize_va_space=2";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Status", id: 1 );
if( get_kb_item( "Policy/linux/sysctl/ssh/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host";
}
else {
	if( get_kb_item( "Policy/linux/sysctl/ERROR" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not run sysctl command";
	}
	else {
		setting = get_kb_item( "Policy/linux/sysctl/kernel.randomize_va_space" );
		if( setting == "2" ) {
			value = "Enabled";
		}
		else {
			value = "Disabled";
		}
		compliant = policy_setting_exact_match( value: value, set_point: default );
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

