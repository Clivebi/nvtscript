if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801469" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)" );
	script_cve_id( "CVE-2010-3174" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Mozilla Products Unspecified Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2010/mfsa2010-64.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_thunderbird_detect_portable_win.sc", "gb_seamonkey_detect_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to cause a denial of service
  or execute arbitrary code." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.0.9

  Thunderbird version before 3.0.9

  Firefox version 3.5.x before 3.5.14" );
	script_tag( name: "insight", value: "The flaw is due to an unspecified vulnerability in the browser engine." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox/Seamonkey/Thunderbird and is prone
  to unspecified vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.5.14 or later

  Upgrade to Thunderbird version 3.0.9 or later

  Upgrade to Seamonkey version 2.0.9 or later" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_in_range( version: ffVer, test_version: "3.5.0", test_version2: "3.5.13" )){
		report = report_fixed_ver( installed_version: ffVer, vulnerable_range: "3.5.0 - 3.5.13" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
smVer = get_kb_item( "Seamonkey/Win/Ver" );
if(smVer){
	if(version_is_less( version: smVer, test_version: "2.0.9" )){
		report = report_fixed_ver( installed_version: smVer, fixed_version: "2.0.9" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
tbVer = get_kb_item( "Thunderbird/Win/Ver" );
if(tbVer){
	if(version_is_less( version: tbVer, test_version: "3.0.9" )){
		report = report_fixed_ver( installed_version: tbVer, fixed_version: "3.0.9" );
		security_message( port: 0, data: report );
	}
}

