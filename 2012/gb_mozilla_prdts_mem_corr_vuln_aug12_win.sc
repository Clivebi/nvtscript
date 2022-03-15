if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803013" );
	script_version( "2020-03-20T12:10:27+0000" );
	script_cve_id( "CVE-2012-1956", "CVE-2012-1971", "CVE-2012-3971", "CVE-2012-3975" );
	script_bugtraq_id( 55249 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-03-20 12:10:27 +0000 (Fri, 20 Mar 2020)" );
	script_tag( name: "creation_date", value: "2012-08-30 01:20:04 +0530 (Thu, 30 Aug 2012)" );
	script_name( "Mozilla Products Memory Corruption Vulnerabilities - August12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50088" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027450" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027451" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-57.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-59.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-64.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_seamonkey_detect_win.sc", "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the browser or cause a denial of service." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.12 on Windows

  Thunderbird version before 15.0 on Windows

  Mozilla Firefox version before 15.0 on Windows" );
	script_tag( name: "insight", value: "- Multiple unspecified errors within the browser engine can be exploited to
  corrupt memory.

  - Errors in 'Silf::readClassMap' and 'Pass::readPass' functions within
  Graphite 2 library.

  - An error within the DOMParser component fails to load sub resources during
  parsing of text/html data within an extension.

  - An error allows shadowing the location object using Object.defineProperty,
  allowing for possible XSS attacks" );
	script_tag( name: "summary", value: "This host is installed with Mozilla firefox/thunderbird/seamonkey and is
  prone to multiple vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 15.0 or later, upgrade to SeaMonkey version to 2.12 or later,
  upgrade to Thunderbird version to 15.0 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_is_less( version: ffVer, test_version: "10.0" ) || version_in_range( version: ffVer, test_version: "11.0", test_version2: "14.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
seaVer = get_kb_item( "Seamonkey/Win/Ver" );
if(seaVer){
	if(version_is_less( version: seaVer, test_version: "2.12" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
tbVer = get_kb_item( "Thunderbird/Win/Ver" );
if(tbVer){
	if(version_is_less( version: tbVer, test_version: "10.0" ) || version_in_range( version: tbVer, test_version: "11.0", test_version2: "14.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

