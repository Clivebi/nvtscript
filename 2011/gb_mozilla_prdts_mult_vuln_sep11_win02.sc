if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802153" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)" );
	script_cve_id( "CVE-2011-2985", "CVE-2011-2986", "CVE-2011-2987", "CVE-2011-2988", "CVE-2011-2989", "CVE-2011-2991", "CVE-2011-2992" );
	script_bugtraq_id( 49224, 49227, 49226, 49242, 49239, 49243, 49245 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Mozilla Products Multiple Vulnerabilities - Sep 11 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45581" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-29.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_seamonkey_detect_win.sc", "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary code in the
  context of the user running an affected application. Failed exploit attempts
  will result in a denial-of-service condition." );
	script_tag( name: "affected", value: "Thunderbird version before 6
  SeaMonkey version 2.0 through 2.2
  Mozilla Firefox version 4.x through 5" );
	script_tag( name: "insight", value: "The flaws are due to

  - An error when using Windows D2D hardware acceleration, allows attacker to
    obtain sensitive image data from a different domain.

  - Heap overflow in the Almost Native Graphics Layer Engine(ANGLE) library
    used in WebGL implementation.

  - Buffer overflow error in the WebGL shader implementation.

  - An error in the browser engine, it fails to implement WebGL, JavaScript

  - An error in the Ogg reader in the browser engine." );
	script_tag( name: "summary", value: "The host is installed with Mozilla firefox/thunderbird/seamonkey
  and is prone to multiple vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 6.0 or later, Upgrade to SeaMonkey version to 2.3 or later,
  Upgrade to Thunderbird version to 6.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Win/Ver" );
if(vers){
	if(version_in_range( version: vers, test_version: "4.0", test_version2: "5.0.1" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "4.0 - 5.0.1" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Seamonkey/Win/Ver" );
if(vers){
	if(version_in_range( version: vers, test_version: "2.0", test_version2: "2.2" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "2.0 - 2.2" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/Win/Ver" );
if(vers){
	if(version_is_less( version: vers, test_version: "6.0" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "6.0" );
		security_message( port: 0, data: report );
	}
}

