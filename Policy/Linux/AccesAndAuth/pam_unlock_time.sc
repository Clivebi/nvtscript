if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150132" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-02-13 07:36:44 +0000 (Thu, 13 Feb 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Lockout time for locked accounts" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_etc_pamd.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "entry", value: "900", id: 1 );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/pam_faillock" );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/pam_tally2" );
	script_tag( name: "summary", value: "The lockout time for locked accounts can be set in two modules:

  - pam_tally2: The login counter (tallying) module

  - pam_faillock: Module counting authentication failures during a specified interval

Use the unlock_time=n option to re-enable login after n seconds after the lock out." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "grep -E '^\\s*auth\\s+required\\s+[pam_faillock.so|pam_tally2.so]\\s+' /etc/pam.d/common-auth /etc/pam.d/password-auth /etc/pam.d/system-auth";
title = "Lockout time for locked accounts";
solution = "Set unlock_time=n option in /etc/pam.d/common-auth, /etc/pam.d/password-auth or /etc/pam.d/system-auth";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
default = "900";
value = "";
if( get_kb_item( "Policy/linux/etc/pam.d/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host possible.";
}
else {
	files = make_list( "/etc/pam.d/common-auth",
		 "/etc/pam.d/password-auth",
		 "/etc/pam.d/system-auth" );
	for file in files {
		if(get_kb_item( "Policy/linux/" + file + "/content/ERROR" )){
			continue;
		}
		content = get_kb_item( "Policy/linux/" + file + "/content" );
		match = eregmatch( string: content, pattern: "\\s*auth\\s+required\\s+(pam_faillock.so|pam_tally2.so)\\s+.+unlock_time=([0-9]*)" );
		if(match){
			if( value == "" ) {
				value = match[2];
			}
			else {
				if(match[2] > value){
					value = match[2];
				}
			}
		}
	}
	if( value == "" ){
		compliant = "no";
		value = "None";
	}
	else {
		compliant = policy_setting_max_match( value: value, set_point: default );
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

