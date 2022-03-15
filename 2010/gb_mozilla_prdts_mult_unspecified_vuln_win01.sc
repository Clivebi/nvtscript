if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801470" );
	script_version( "2019-08-06T11:17:21+0000" );
	script_tag( name: "last_modification", value: "2019-08-06 11:17:21 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "creation_date", value: "2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)" );
	script_cve_id( "CVE-2010-3176" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Mozilla Products Multiple Unspecified Vulnerabilities October-10(Windows)" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2010/mfsa2010-64.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_thunderbird_detect_portable_win.sc", "gb_seamonkey_detect_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to cause a denial of service
  or execute arbitrary code." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.0.9

  Thunderbird version before 3.0.9 and 3.1.x before 3.1.5

  Firefox version 3.5.x before 3.5.14 and 3.6.x before 3.6.11" );
	script_tag( name: "insight", value: "The flaws are due to multiple unspecified vulnerabilities in the
  browser engine." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox/Seamonkey/Thunderbird and is prone
  to multiple vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.6.11 or 3.5.14 or later

  Upgrade to Thunderbird version 3.1.5 or 3.0.9 or later

  Upgrade to Seamonkey version 2.0.9 or later" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_in_range( version: ffVer, test_version: "3.6.0", test_version2: "3.6.10" ) || version_in_range( version: ffVer, test_version: "3.5.0", test_version2: "3.5.13" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
smVer = get_kb_item( "Seamonkey/Win/Ver" );
if(smVer){
	if(version_is_less( version: smVer, test_version: "2.0.9" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
tbVer = get_kb_item( "Thunderbird/Win/Ver" );
if(tbVer){
	if(version_is_less( version: tbVer, test_version: "3.0.9" ) || version_in_range( version: tbVer, test_version: "3.1.0", test_version2: "3.1.4" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

