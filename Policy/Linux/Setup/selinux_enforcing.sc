if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109740" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2019-01-16 08:27:48 +0100 (Wed, 16 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: SELinux state" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_etc_selinux_config.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Status", type: "radio", value: "Enabled;Disabled", id: 1 );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/selinux" );
	script_tag( name: "summary", value: "Security Enhanced Linux (SELinux) use the Linux Security Modules
and provides Mandatory Access Control (MAC). A MAC kernel protects the system from malicious apps.
To ensure SELinux functionality is in effect all times it has to be enabled at boot time." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "grep 'SELINUX=enforcing' /etc/selinux/config";
title = "Enforce SELinux";
solution = "Add 'SELINUX=enforcing' to /etc/selinux/conf";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Status", id: 1 );
if( get_kb_item( "Policy/linux//etc/selinux/config/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host";
}
else {
	if( get_kb_item( "Policy/linux//etc/selinux/config/ERROR" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not read /etc/selinux/config";
	}
	else {
		content = get_kb_item( "Policy/linux//etc/selinux/config/content" );
		grep = egrep( string: content, pattern: "SELINUX\\=enforcing" );
		for line in split( grep ) {
			if(IsMatchRegexp( line, "^\\s*#" )){
				continue;
			}
			value = "Enabled";
		}
		if(!value){
			value = "Disabled";
		}
		compliant = policy_setting_exact_match( value: value, set_point: default );
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

