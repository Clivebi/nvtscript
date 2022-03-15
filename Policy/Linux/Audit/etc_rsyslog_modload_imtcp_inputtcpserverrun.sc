if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150165" );
	script_version( "2021-05-18T12:49:08+0000" );
	script_tag( name: "last_modification", value: "2021-05-18 12:49:08 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2020-03-16 11:10:17 +0000 (Mon, 16 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Only designated log hosts accepts remote rsyslog messages" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_etc_rsyslog_conf.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/rsyslog.conf" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored)" );
	script_xref( name: "Policy", value: "CIS CentOS Linux 8 Benchmark v1.0.0: 4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 9.2 Ensure Only Approved Ports Protocols and Services Are Running" );
	script_tag( name: "summary", value: "Input plugin for plain TCP syslog. Replaces the deprecated -t
option. Can be used like this:

  - $ModLoad imtcp

  - $InputTCPServerRun 514" );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "grep '$ModLoad' /etc/rsyslog.conf, grep '$InputTCPServerRun' /etc/rsyslog.conf";
title = "'$ModLoad imtcp' and '$InputTCPServerRun 514' in /etc/rsyslog.conf";
solution = "Add '$ModLoad imtcp' and '$InputTCPServerRun 514' to /etc/rsyslog.conf";
test_type = "SSH_Cmd";
default = "ModLoad imtcp, InputTCPServerRun 514";
if( get_kb_item( "Policy/linux//etc/rsyslog.conf/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host";
}
else {
	if( get_kb_item( "Policy/linux//etc/rsyslog.conf/content/ERROR" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not read /etc/rsyslog.conf";
	}
	else {
		content = get_kb_item( "Policy/linux//etc/rsyslog.conf/content" );
		value = egrep( string: content, pattern: "\\$(ModLoad\\s+imtcp|InputTCPServerRun\\s+514)" );
		for line in split( value ) {
			if(IsMatchRegexp( line, "^\\s*#" )){
				continue;
			}
			if(IsMatchRegexp( line, "imtcp" )){
				imtcp = TRUE;
			}
			if(IsMatchRegexp( line, "InputTCPServerRun" )){
				InputTCPServerRun = TRUE;
			}
		}
		if( imtcp && InputTCPServerRun ) {
			compliant = "yes";
		}
		else {
			compliant = "no";
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

