if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105377" );
	script_bugtraq_id( 76762 );
	script_cve_id( "CVE-2015-6295" );
	script_tag( name: "cvss_base", value: "4.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:N/A:P" );
	script_version( "$Revision: 11872 $" );
	script_name( "Cisco NX-OS Software TACACS+ Server Local Privilege Escalation Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/viewAlert.x?alertId=40990" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-09-21 11:41:15 +0200 (Mon, 21 Sep 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_nx_os_version.sc" );
	script_mandatory_keys( "cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device" );
	script_tag( name: "impact", value: "An unauthenticated, adjacent attacker could exploit this vulnerability to cause a DoS condition. A successful exploit may also impact confidentiality due to errors in handling network packets." );
	script_tag( name: "vuldetect", value: "Check the NX OS version." );
	script_tag( name: "insight", value: "This issue is being tracked by Cisco Bug ID CSCuw13560" );
	script_tag( name: "solution", value: "See the vendor advisory for a solution" );
	script_tag( name: "summary", value: "Cisco Nexus 9000 Series Switches contain a vulnerability that could allow an unauthenticated, adjacent attacker to cause a denial of service condition." );
	script_tag( name: "affected", value: "Nexus 9000 Series 7.0(3)I1(1) and 6.1(2)I3(4)" );
	exit( 0 );
}
if(!device = get_kb_item( "cisco_nx_os/device" )){
	exit( 0 );
}
if(!ContainsString( device, "Nexus" )){
	exit( 0 );
}
if(!nx_model = get_kb_item( "cisco_nx_os/model" )){
	exit( 0 );
}
if(!IsMatchRegexp( nx_model, "^N9K" )){
	exit( 99 );
}
if(!nx_ver = get_kb_item( "cisco_nx_os/version" )){
	exit( 0 );
}
if(nx_ver == "6.1(2)I3(4)" || nx_ver == "7.0(3)I1(1)"){
	security_message( port: 0, data: "Installed Version: " + nx_ver + "\nFixed Version:     NA" );
	exit( 0 );
}
exit( 99 );

