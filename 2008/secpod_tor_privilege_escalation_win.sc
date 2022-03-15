if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900423" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5397", "CVE-2008-5398" );
	script_bugtraq_id( 32648 );
	script_name( "TOR Privilege Escalation Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.torproject.org" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/33025" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker gain privileges and escalate
  the privileges in malicious ways." );
	script_tag( name: "affected", value: "Tor version 0.2.0.31 or prior." );
	script_tag( name: "insight", value: "The flaws are due to

  - an application does not properly drop privileges to the primary groups of
  the user specified by the User Parameter.

  - a ClientDNSRejectInternalAddresses configuration option is not always
  enforced which weaknesses the application security." );
	script_tag( name: "solution", value: "Upgrade to the latest version 0.2.0.32." );
	script_tag( name: "summary", value: "This host is installed with TOR and is prone to Privilege
  Escalation vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
torVer = registry_get_sz( item: "DisplayName", key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Tor" );
if(!torVer){
	exit( 0 );
}
torVer = eregmatch( pattern: "Tor ([0-9.]+)", string: torVer );
if(torVer[1] != NULL){
	if(version_is_less_equal( version: torVer[1], test_version: "0.2.0.31" )){
		report = report_fixed_ver( installed_version: torVer[1], vulnerable_range: "Less than or equal to 0.2.0.31" );
		security_message( port: 0, data: report );
	}
}

