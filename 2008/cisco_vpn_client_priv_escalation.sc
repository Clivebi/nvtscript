if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.25550" );
	script_version( "2019-10-09T06:43:33+0000" );
	script_tag( name: "last_modification", value: "2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2006-2679" );
	script_bugtraq_id( 18094 );
	script_xref( name: "OSVDB", value: "25888" );
	script_name( "Cisco VPN Client Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_family( "Windows" );
	script_copyright( "This script is Copyright (C) 2008 Ferdy Riphagen" );
	script_dependencies( "cisco_vpn_client_detect.sc" );
	script_mandatory_keys( "SMB/CiscoVPNClient/Version" );
	script_tag( name: "solution", value: "Upgrade to version 4.8.01.0300 or a later." );
	script_tag( name: "summary", value: "The installed Cisco VPN Client version is prone to a privilege
  escalation attack." );
	script_tag( name: "insight", value: "By using the 'Start before logon' feature in the
  VPN client dialer, a local attacker may gain privileges and execute
  arbitrary commands with SYSTEM privileges." );
	script_xref( name: "URL", value: "http://www.cisco.com/warp/public/707/cisco-sa-20060524-vpnclient.shtml" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
version = get_kb_item( "SMB/CiscoVPNClient/Version" );
if(version){
	if(ContainsString( version, "4.7.00.0533" )){
		exit( 0 );
	}
	if(egrep( pattern: "^([23]\\.|4\\.([067]\\.|8\\.00)).+", string: version )){
		report = report_fixed_ver( installed_version: version, fixed_version: "4.8.01.0300" );
		security_message( port: 0, data: report );
	}
}

