if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900967" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3587", "CVE-2009-3588" );
	script_bugtraq_id( 36653 );
	script_name( "CA Multiple Products 'arclib' Component DoS Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_ca_mult_prdts_detect_win.sc" );
	script_mandatory_keys( "CA/Multiple_Products/Win/Installed" );
	script_require_ports( 139, 445 );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53697" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/53698" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2852" );
	script_xref( name: "URL", value: "https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=218878" );
	script_tag( name: "impact", value: "Remote attackers can exploit this issue to execute arbitrary code and
  crash the service on affected systems via specially crafted RAR files." );
	script_tag( name: "affected", value: "eTrust EZ Antivirus 7.1

  CA Anti-Virus 2007 through 2008

  CA Internet Security Suite 2007 through Plus 2009" );
	script_tag( name: "insight", value: "Multiple errors occur in the arclib component of the CA Anti-Virus engine
  due to improper handling of RAR files." );
	script_tag( name: "summary", value: "This host is installed with CA Multiple Products and is prone to
  Denial of Service vulnerability." );
	script_tag( name: "solution", value: "Apply the appropriate patches from the referenced advisory." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
ezavVer = get_kb_item( "CA/eTrust-EZ-AV/Win/Ver" );
caavVer = get_kb_item( "CA/AV/Win/Ver" );
caissVer = get_kb_item( "CA/ISS/Win/Ver" );
if(IsMatchRegexp( ezavVer, "^7\\.1" ) || IsMatchRegexp( caavVer, "^(8|9|10)\\..*" ) || IsMatchRegexp( caissVer, "^(3|4|5)\\..*" )){
	dllPath = registry_get_sz( key: "SOFTWARE\\ComputerAssociates\\ISafe", item: "ArclibDllPath" );
	share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: dllPath );
	file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: dllPath );
	dllVer = GetVer( file: file, share: share );
	if(dllVer && version_is_less( version: dllVer, test_version: "8.1.4.0" )){
		report = report_fixed_ver( installed_version: dllVer, fixed_version: "See references" );
		security_message( port: 0, data: report );
	}
}

