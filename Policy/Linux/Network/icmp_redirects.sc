if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109758" );
	script_version( "2021-05-14T14:03:39+0000" );
	script_tag( name: "last_modification", value: "2021-05-14 14:03:39 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "creation_date", value: "2019-01-24 11:47:08 +0100 (Thu, 24 Jan 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: ICMP Redirect (accept)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "read_etc_sysctl_d.sc", "read_and_parse_sysctl.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Status", type: "radio", value: "Disabled;Enabled", id: 1 );
	script_xref( name: "URL", value: "https://linux.die.net/man/5/sysctl.conf" );
	script_xref( name: "URL", value: "https://www.cyberciti.biz/faq/linux-kernel-etcsysctl-conf-security-hardening/" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 3.2.2 Ensure ICMP redirects are not accepted (Scored)" );
	script_xref( name: "Policy", value: "CIS CentOS Linux 8 Benchmark v1.0.0: 3.2.2 Ensure ICMP redirects are not accepted (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 5.1 Establish Secure Configurations" );
	script_tag( name: "summary", value: "ICMP Redirects are used to update a hosts routing information,
if e.g. an alternative and possible more direct route is available.
If the host does not act as a router, ICMP Redirects are not needed. Further more, an attacker could
use corrupt routing to have users access a system set up by the attacker.
This script tests whether the Linux host is configured to accept ICMP Redirects." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "sysctl net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects";
title = "Accept ICMP Redirects";
solution = "Set the parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file and run 'sysctl -w SETTING = VALUE'";
test_type = "SSH_Cmd";
default = script_get_preference( name: "Status", id: 1 );
if( get_kb_item( "Policy/linux/sysctl/conf/ERROR" ) || get_kb_item( "Policy/linux/sysctl/ssh/ERROR" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection to host";
}
else {
	if( get_kb_item( "Policy/linux//etc/sysctl.conf/content/ERROR" ) || get_kb_item( "Policy/linux/sysctl/ERROR" ) ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not read /etc/sysctl.conf or run sysctl";
	}
	else {
		sysctl_d_files = get_kb_list( "Policy/linux//etc/sysctl.d/*/content" );
		content_list = make_list( sysctl_d_files,
			 get_kb_item( "Policy/linux//etc/sysctl.conf/content" ) );
		for content in content_list {
			if(IsMatchRegexp( content, "net\\.ipv4\\.conf\\.all\\.accept_redirects\\s*=\\s*1" ) || IsMatchRegexp( content, "net\\.ipv4\\.conf\\.default\\.accept_redirects\\s*=\\s*1" ) || IsMatchRegexp( content, "net\\.ipv6\\.conf\\.all\\.accept_redirects\\s*=\\s*1" ) || IsMatchRegexp( content, "net\\.ipv6\\.conf\\.default\\.accept_redirects\\s*=\\s*1" )){
				value = "Enabled";
			}
		}
		net_ipv4_conf_all_accept_redirects = get_kb_item( "Policy/linux/sysctl/net.ipv4.conf.all.accept_redirects" );
		net_ipv4_conf_default_accept_redirects = get_kb_item( "Policy/linux/sysctl/net.ipv4.conf.default.accept_redirects" );
		net_ipv6_conf_all_accept_redirects = get_kb_item( "Policy/linux/sysctl/net.ipv6.conf.all.accept_redirects" );
		net_ipv6_conf_default_accept_redirects = get_kb_item( "Policy/linux/sysctl/net.ipv6.conf.default.accept_redirects" );
		if(net_ipv4_conf_all_accept_redirects != "0" || net_ipv4_conf_default_accept_redirects != "0" || net_ipv6_conf_all_accept_redirects != "0" || net_ipv6_conf_default_accept_redirects != "0"){
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

