if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150320" );
	script_version( "2020-11-09T15:35:56+0000" );
	script_tag( name: "last_modification", value: "2020-11-09 15:35:56 +0000 (Mon, 09 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-09 15:16:41 +0000 (Mon, 09 Nov 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: sysctl kernel.shmall" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_and_parse_sysctl.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/sysctl" );
	script_xref( name: "URL", value: "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/5/html/tuning_and_optimizing_red_hat_enterprise_linux_for_oracle_9i_and_10g_databases/chap-oracle_9i_and_10g_tuning_guide-setting_shared_memory" );
	script_tag( name: "summary", value: "This parameter sets the total amount of shared memory pages that
can be used system wide." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "sysctl kernel.shmall";
title = "sysctl kernel.shmall";
solution = "sysctl -w kernel.shmall = VALUE";
test_type = "Manual Check";
default = "None";
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
		if( !value = get_kb_item( "Policy/linux/sysctl/kernel.shmall" ) ){
			value = "Error";
			compliant = "incomplete";
			comment = "Could not find setting with sysctl.";
		}
		else {
			compliant = "incomplete";
			comment = "Please test the compliance status manually";
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

