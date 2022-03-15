if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802151" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)" );
	script_cve_id( "CVE-2011-2982", "CVE-2011-2983" );
	script_bugtraq_id( 49216, 49223 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Mozilla Products Multiple Vulnerabilities - Sep 11 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45666/" );
	script_xref( name: "URL", value: "http://support.avaya.com/css/P8/documents/100146973" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-30.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_seamonkey_detect_win.sc", "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code in
  the context of the user running an affected application. Failed exploit
  attempts will result in a denial-of-service condition." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 3.6.20
  SeaMonkey version 1.x and 2.0 through 2.2
  Thunderbird version 2.x and 3.0 through 3.1.11" );
	script_tag( name: "insight", value: "The flaws are due to

  - Unspecified errors in the browser engine in mozilla products.

  - Improperly handling of the 'RegExp.input' property, which allows remote
    attackers to bypass the same origin policy and read data from a different
    domain via a crafted web site." );
	script_tag( name: "summary", value: "The host is installed with Mozilla firefox/thunderbird/seamonkey
  and is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 3.6.20 or later, Upgrade to SeaMonkey version to 2.3 or later,
  Upgrade to Thunderbird version to 3.1.12 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Win/Ver" );
if(vers){
	if(version_is_less( version: vers, test_version: "3.6.20" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vers = get_kb_item( "Seamonkey/Win/Ver" );
if(vers){
	if(IsMatchRegexp( vers, "^1\\." ) || version_in_range( version: vers, test_version: "2.0", test_version2: "2.2" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/Win/Ver" );
if(vers){
	if(IsMatchRegexp( vers, "^2\\." ) || version_in_range( version: vers, test_version: "3.0", test_version2: "3.1.11" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

