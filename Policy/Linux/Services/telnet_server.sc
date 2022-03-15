if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150514" );
	script_version( "2021-03-12T14:19:08+0000" );
	script_tag( name: "last_modification", value: "2021-03-12 14:19:08 +0000 (Fri, 12 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-01-04 10:57:26 +0000 (Mon, 04 Jan 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "70" );
	script_name( "Linux: Disabled telnet server" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_etc_inetd_xinetd_files.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 2.1.8 Ensure telnet server is not enabled (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 9.2 Ensure Only Approved Ports Protocols and Services Are Running" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 4.5 Use Multifactor Authentication For All Administrative Access" );
	script_tag( name: "summary", value: "The telnet-server package contains the telnet daemon, which
accepts connections from users from other systems via the telnet protocol." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "grep -R '^telnet' /etc/inetd.*; grep 'disabled = yes' /etc/xinetd.d/telnet";
title = "Disabled telnet services";
solution = "Comment out or remove any lines starting with telnet from /etc/inetd.conf and /etc/inetd.d/* .
Set disable = yes on all telnet services in /etc/xinetd.conf and /etc/xinetd.d/*.";
test_type = "SSH_Cmd";
default = "Disabled";
if( get_kb_item( "Policy/linux/inetd/ssh/ERROR" ) || get_kb_item( "Policy/linux/xinetd/ssh/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Can not login to the host";
}
else {
	if( get_kb_item( "Policy/linux/inetd/ERROR" ) && get_kb_item( "Policy/linux/xinetd/ERROR" ) ){
		compliant = "yes";
		value = "Disabled";
		comment = "No /etc/inetd.* and /etc/xinetd* files found";
	}
	else {
		files = get_kb_list( "Policy/linux//etc/inetd*" );
		for key in keys( files ) {
			if(egrep( string: files[key], pattern: "^\\s*telnet" )){
				compliant = "no";
				value = "Enabled";
				comment = "Found in /etc/inetd.* file";
				break;
			}
		}
		if(!value){
			if(file = get_kb_item( "Policy/linux//etc/xinetd.d/telnet/content" )){
				if(!IsMatchRegexp( file, "disable\\s*=\\s*yes" )){
					compliant = "no";
					value = "Enabled";
					comment = "Found in /etc/xinetd.d/telnet file";
				}
			}
		}
		if(!value){
			if(telnet_service = get_kb_item( "Policy/linux/etc/xinetd.conf/telnet" )){
				if(!IsMatchRegexp( telnet_service, "disable\\s*=\\s*yes" )){
					compliant = "no";
					value = "Enabled";
					comment = "Found in /etc/xinetd.conf file";
				}
			}
		}
		if(!value){
			compliant = "yes";
			value = "Disabled";
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

