if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801499" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)" );
	script_cve_id( "CVE-2010-3777" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Mozilla Products Multiple Vulnerabilities-01 dec-10 (Windows)" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2010/mfsa2010-74.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause a denial of
  service or possibly execute arbitrary code via unknown vectors." );
	script_tag( name: "affected", value: "Thunderbird version 3.1.x before 3.1.7

  Firefox version before 3.5.16 and 3.6.x before 3.6.13" );
	script_tag( name: "insight", value: "The flaw is due to unspecified vulnerability which allows remote
  attackers to cause a denial of service." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox/Thunderbird that are
  prone to multiple vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.5.16 or 3.6.13 or later

  Upgrade to Thunderbird version 3.1.7 or later" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_in_range( version: ffVer, test_version: "3.6", test_version2: "3.6.13" ) || version_is_less( version: ffVer, test_version: "3.5.16" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
tbVer = get_kb_item( "Thunderbird/Win/Ver" );
if(tbVer){
	if(version_in_range( version: tbVer, test_version: "3.1", test_version2: "3.1.7" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

