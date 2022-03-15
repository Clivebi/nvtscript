if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150266" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-06-11 12:44:32 +0000 (Thu, 11 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: minclass in pam_pwquality.so" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_etc_pamd.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "entry", value: "3", id: 1 );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/pam_pwquality" );
	script_tag( name: "summary", value: "The pam_pwquality module can be plugged into the password stack
of a given service to provide some plug-in strength-checking for passwords. The code was originally
based on pam_cracklib module and the module is backwards compatible with its options.

  - minclass: The minimum number of required classes of characters for the new password. The default
number is zero. The four classes are digits, upper and lower letters and other characters. The
difference to the credit check is that a specific class if of characters is not required. Instead
N out of four of the classes are required." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "grep minclass /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/common-password";
title = "Minimum number of required classes of characters for the new password";
solution = "Set minclass=VALUE in /etc/pam.d/common-password, /etc/pam.d/password-auth or /etc/pam.d/system-auth";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "Policy/linux/etc/pam.d/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host possible.";
}
else {
	files = make_list( "/etc/pam.d/system-auth",
		 "/etc/pam.d/password-auth",
		 "/etc/pam.d/common-password" );
	for file in files {
		if(get_kb_item( "Policy/linux/" + file + "/content/ERROR" )){
			continue;
		}
		content = get_kb_item( "Policy/linux/" + file + "/content" );
		password_required_pam_pwquality = egrep( string: content, pattern: "pam_pwquality.so" );
		for line in split( buffer: password_required_pam_pwquality, keep: FALSE ) {
			minclass_match = eregmatch( string: line, pattern: "minclass=([0-9]+)" );
			if(minclass_match){
				value = minclass_match[1];
			}
		}
	}
	if( !value ){
		value = "None";
		compliant = "no";
		comment = "Could not find minclass option";
	}
	else {
		compliant = policy_setting_exact_match( value: int( value ), set_point: int( default ) );
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

