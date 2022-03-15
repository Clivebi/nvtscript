if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150225" );
	script_version( "2021-01-19T15:26:02+0000" );
	script_tag( name: "last_modification", value: "2021-01-19 15:26:02 +0000 (Tue, 19 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-05-07 06:49:26 +0000 (Thu, 07 May 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: SSH Ciphers" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_sshd_config.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "entry", value: "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr", id: 1 );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/sshd_config" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 5.2.13 Ensure only strong Ciphers are used (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 14.4 Encrypt All Sensitive Information in Transit" );
	script_tag( name: "summary", value: "sshd reads configuration data from /etc/ssh/sshd_config (or the
file specified with -f on the command line). The file contains keyword-argument pairs, one per line.
Lines starting with '#' and empty lines are interpreted as comments. Arguments may optionally be
enclosed in double quotes in order to represent arguments containing spaces.

  - Ciphers: Specifies the ciphers allowed for protocol version 2. Multiple ciphers must be
comma-separated.

Note: The VT does not check for exact match, but if any other than the given ciphers is found." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "grep '^Ciphers' /etc/ssh/sshd_config";
title = "SSH Ciphers";
solution = "Edit /etc/ssh/sshd_config";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "linux/mount/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Could not read /etc/ssh/sshd_config";
}
else {
	value = get_kb_item( "Policy/linux/sshd_config/ciphers" );
	if( !value ){
		value = "Error";
		compliant = "incomplete";
		comment = "Could not get supported ciphers from /etc/ssh/sshd_config";
	}
	else {
		compliant = "yes";
		for cipher in policy_build_list_from_string( str: value ) {
			if(!ContainsString( default, cipher )){
				compliant = "no";
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

