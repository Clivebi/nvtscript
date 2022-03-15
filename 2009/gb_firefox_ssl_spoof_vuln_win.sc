if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800915" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-2408", "CVE-2009-2409" );
	script_bugtraq_id( 35888 );
	script_name( "Firefox SSL Server Spoofing Vulnerability (Windows)" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=510251" );
	script_xref( name: "URL", value: "http://www.wired.com/threatlevel/2009/07/kaminsky/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Attackers can exploit this issue via specially crafted certificates
  to spoof arbitrary SSL servers." );
	script_tag( name: "affected", value: "Mozilla Firefox versions prior to 3.5
  NSS versions prior to 3.12.3 on Windows." );
	script_tag( name: "insight", value: "- Lack of validation of domain name in a signed X.509 certificate lead
  to an error while processing a '\\0' character in a domain name in the
  subject's common Name (CN) field.

  - Lack of validation of the MD2 hash in a signed X.509 certificate can
  be exploited to generate fake intermediate SSL certificate that would
    be accepted as if it was authentic." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 3.5 or NSS version 3.12.3 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone
  to SSL server spoofing vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
firefoxVer = get_kb_item( "Firefox/Win/Ver" );
if(!firefoxVer){
	exit( 0 );
}
if(version_is_less( version: firefoxVer, test_version: "3.5" )){
	dllPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" + "\\App Paths\\firefox.exe", item: "Path" );
	if(dllPath != NULL){
		share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: dllPath );
		file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: dllPath + "\\nss3.dll" );
		dllVer = GetVer( share: share, file: file );
		if(dllVer != NULL){
			if(version_is_less( version: dllVer, test_version: "3.12.3" )){
				report = report_fixed_ver( installed_version: dllVer, fixed_version: "3.12.3" );
				security_message( port: 0, data: report );
			}
		}
	}
}

