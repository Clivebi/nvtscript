if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103879" );
	script_bugtraq_id( 64670 );
	script_cve_id( "CVE-2013-6982" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_version( "$Revision: 11867 $" );
	script_name( "Cisco NX-OS BGP Message Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/64670" );
	script_xref( name: "URL", value: "https://tools.cisco.com/bugsearch/bug/CSCuj03174" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2014-01-13 10:35:00 +0100 (Mon, 13 Jan 2014)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_nx_os_version.sc" );
	script_mandatory_keys( "cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device" );
	script_tag( name: "impact", value: "An attacker can exploit this issue to cause all BGP sessions on the
device to reset, denying service to legitimate users." );
	script_tag( name: "vuldetect", value: "Check the NX OS version." );
	script_tag( name: "insight", value: "This issue is being tracked by Cisco Bug ID CSCuj03174." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Cisco NX-OS is prone to denial-of-service vulnerability because it
fails to properly handle the BGP updates." );
	script_tag( name: "affected", value: "Cisco Nexus 7000 running NX-OS 6.2(2)S27" );
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
if(!nx_ver = get_kb_item( "cisco_nx_os/version" )){
	exit( 0 );
}
if(!IsMatchRegexp( nx_model, "^7" )){
	exit( 99 );
}
if(nx_ver == "6.2(2)S27"){
	security_message( port: 0, data: "Installed Version: " + nx_ver + "\nFixed Version:     7.0(0)ZD(0.132)" );
	exit( 0 );
}
exit( 99 );

