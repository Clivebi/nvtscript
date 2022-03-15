if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150559" );
	script_version( "2021-01-22T09:12:45+0000" );
	script_tag( name: "last_modification", value: "2021-01-22 09:12:45 +0000 (Fri, 22 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-15 13:47:26 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: SSH HostKeyAlgorithms" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_sshd_config.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Value", type: "entry", value: "pgp-sign-rsa,pgp-sign-dss,ecdsa-sha2-*,x509v3-rsa2048-sha256,x509v3-ecdsa-sha2-*", id: 1 );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/sshd_config" );
	script_tag( name: "summary", value: "sshd reads configuration data from /etc/ssh/sshd_config (or the
file specified with -f on the command line). The file contains keyword-argument pairs, one per line.
Lines starting with '#' and empty lines are interpreted as comments. Arguments may optionally be
enclosed in double quotes in order to represent arguments containing spaces.

HostKeyAlgorithms specifies the host key algorithms that the client wants to use in order of preference" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
cmd = "grep '^HostKeyAlgorithms' /etc/ssh/sshd_config";
title = "SSH HostKeyAlgorithms";
solution = "Edit /etc/ssh/sshd_config";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Value", id: 1 );
if( get_kb_item( "Policy/linux/sshd_config/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Could not read /etc/ssh/sshd_config";
}
else {
	value = get_kb_item( "Policy/linux/sshd_config/hostkeyalgorithms" );
	if( !value ){
		value = "Error";
		compliant = "incomplete";
		comment = "Could not get supported HostKeyAlgorithms from /etc/ssh/sshd_config";
	}
	else {
		compliant = "yes";
		default_list = policy_build_list_from_string( str: default );
		for algorithm in policy_build_list_from_string( str: value ) {
			allowed = FALSE;
			for default_alg in default_list {
				if(!egrep( string: algorithm, pattern: default_alg )){
					continue;
				}
				allowed = TRUE;
			}
			if(!allowed){
				compliant = "no";
				comment += algorithm + "\n";
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

