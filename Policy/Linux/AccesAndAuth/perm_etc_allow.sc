if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150102" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-01-24 09:25:45 +0100 (Fri, 24 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Permissions on /etc/cron.allow" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "stat_cron_files.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Permissions", type: "entry", value: "700", id: 1 );
	script_add_preference( name: "Owner", type: "entry", value: "root:root", id: 2 );
	script_xref( name: "URL", value: "https://linux.die.net/man/1/crontab" );
	script_xref( name: "URL", value: "https://linux.die.net/man/2/stat" );
	script_tag( name: "summary", value: "The cron.allow file controls administrative access to the
crontab command for scheduling and modifying cron jobs." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
cmd = "stat /etc/cron.allow";
title = "Permissions on /etc/cron.allow";
solution = "chmod PERMISSIONS /etc/cron.allow; chown USER:GROUP /etc/cron.allow";
test_type = "SSH_Cmd";
default_permissions = script_get_preference( name: "Permissions", id: 1 );
default_owner = script_get_preference( name: "Owner", id: 2 );
default = "Permissions:" + default_permissions + ", Owner:" + default_owner;
if( get_kb_item( "Policy/linux/cron/ERROR" ) || get_kb_item( "Policy/linux/cron//etc/cron.allow/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Could not get information about /etc/cron.allow file.";
}
else {
	permissions = get_kb_item( "Policy/linux/cron//etc/cron.allow/perm" );
	owner = get_kb_item( "Policy/linux/cron//etc/cron.allow/user_group" );
	if( policy_access_permissions_match_or_stricter( value: permissions, set_point: default_permissions ) == "yes" && policy_setting_exact_match( value: owner, set_point: default_owner ) == "yes" ){
		compliant = "yes";
	}
	else {
		compliant = "no";
	}
	value = "Permissions:" + permissions + ", Owner:" + owner;
	comment = "";
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

