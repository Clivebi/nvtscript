if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802842" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-0475" );
	script_bugtraq_id( 53230 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-05-02 12:29:17 +0530 (Wed, 02 May 2012)" );
	script_name( "Mozilla Products Security Bypass Vulnerability - May12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48972/" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48932/" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1026971" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-28.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_seamonkey_detect_win.sc", "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to inject scripts or bypass
  certain security restrictions." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.9
  Thunderbird version 5.0 through 11.0
  Mozilla Firefox version 4.x through 11.0" );
	script_tag( name: "insight", value: "The flaw is due to an error within the handling of XMLHttpRequest
  and WebSocket while using an IPv6 address can be exploited to bypass the
  same origin policy." );
	script_tag( name: "summary", value: "This host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to security bypass vulnerability" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 12.0 or later.

  Upgrade to SeaMonkey version to 2.9 or later.

  Upgrade to Thunderbird version to 12.0 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Win/Ver" );
if(vers){
	if(version_in_range( version: vers, test_version: "4.0", test_version2: "11.0" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "4.0 - 11.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Seamonkey/Win/Ver" );
if(vers){
	if(version_is_less( version: vers, test_version: "2.9" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "2.9" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/Win/Ver" );
if(vers){
	if(version_in_range( version: vers, test_version: "5.0", test_version2: "11.0" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "5.0 - 11.0" );
		security_message( port: 0, data: report );
	}
}

