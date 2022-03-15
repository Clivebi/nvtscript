if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800150" );
	script_version( "2020-04-27T11:01:03+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 11:01:03 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2008-12-04 14:15:00 +0100 (Thu, 04 Dec 2008)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-5005" );
	script_bugtraq_id( 32072 );
	script_name( "Alpine tmail and dmail Buffer Overflow Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://www.washington.edu/alpine/" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32483" );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/3042/products" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation allows execution of arbitrary code, but requires
  that the utilities are configured as a delivery backend for a mail transfer
  agent allowing overly long destination mailbox names." );
	script_tag( name: "affected", value: "University of Washington Alpine 2.00 and priror on Windows." );
	script_tag( name: "insight", value: "The flaws are due to boundary error in the tmail/dmail utility,
  when processing overly long mailbox names composed of a username and +
  character followed by a long string and also by specifying a long folder
  extension argument on the command line." );
	script_tag( name: "summary", value: "The host has Alpine installed and is prone to Buffer Overflow
  Vulnerabilities." );
	script_tag( name: "solution", value: "Update to a higher version." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
apVer = registry_get_sz( item: "DisplayName", key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Alpine_is1" );
if(!apVer){
	exit( 0 );
}
apVer = apVer - "Alpine ";
if(version_is_less_equal( version: apVer, test_version: "2.00" )){
	report = report_fixed_ver( installed_version: apVer, vulnerable_range: "Less than or equal to 2.00" );
	security_message( port: 0, data: report );
}

