if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902306" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)" );
	script_cve_id( "CVE-2010-3400" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_name( "Mozilla Products 'js_InitRandom' Information Disclosure Vulnerability (Windows)" );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=475585" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_seamonkey_detect_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to guess the seed value
  via a brute-force attack." );
	script_tag( name: "affected", value: "Mozilla Firefox version 3.5.x before 3.5.10

  Mozilla Firefox version 3.6.x before 3.6.4

  SeaMonkey version before 2.0.5." );
	script_tag( name: "insight", value: "The flaw is due to error in 'js_InitRandom' function in the
  JavaScript implementation uses the current time for seeding of a random number generator." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox and is prone to
  Information Disclosure Vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 3.5.10 or 3.6.4 or later and
  Seamonkey version 2.0.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_in_range( version: ffVer, test_version: "3.5.0", test_version2: "3.5.9" ) || version_in_range( version: ffVer, test_version: "3.6.0", test_version2: "3.6.3" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
seaVer = get_kb_item( "Seamonkey/Win/Ver" );
if(seaVer){
	if(version_is_less( version: seaVer, test_version: "2.0.5" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

