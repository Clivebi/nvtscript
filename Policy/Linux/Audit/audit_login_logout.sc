if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109779" );
	script_version( "2020-07-29T09:51:47+0000" );
	script_tag( name: "last_modification", value: "2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)" );
	script_tag( name: "creation_date", value: "2019-02-05 14:45:03 +0100 (Tue, 05 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Audit login / logout" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_etc_audit_audit_rules.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://linux.die.net/man/7/audit.rules" );
	script_tag( name: "summary", value: "Monitoring login and logoff events can provide evidence for
compromised user accounts or brute force attacks.
This script checks if write access to '/var/log/faillog', '/var/log/lastlog' and '/var/log/tallylog'
files is monitored." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "grep '*.warning' /etc/rsyslog.conf";
title = "Log all facility messages with warning priority to specified files";
solution = "Add '*.warning FILE' to /etc/rsyslog.conf";
test_type = "SSH_Cmd";
default = "-w /var/log/faillog -p wa -k logins,-w /var/log/lastlog -p wa -k logins,-w /var/log/tallylog -p wa -k logins";
if( get_kb_item( "Policy/linux//etc/audit/audit.rules/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host";
}
else {
	if( get_kb_item( "Policy/linux//etc/audit/audit.rules/content/ERROR" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not read /etc/audit/audit.rules";
	}
	else {
		content = get_kb_item( "Policy/linux//etc/audit/audit.rules/content" );
		grep = egrep( string: content, pattern: "-w /var/log/(fail|last|tally)log -p wa -k logins" );
		for line in split( grep ) {
			if(IsMatchRegexp( line, "^\\s*#" )){
				continue;
			}
			value += "," + chomp( line );
		}
		if( value ) {
			value = str_replace( string: value, find: ",", replace: "", count: 1 );
		}
		else {
			value = "None";
		}
		compliant = policy_settings_lists_match( value: value, set_points: default, sep: "," );
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

