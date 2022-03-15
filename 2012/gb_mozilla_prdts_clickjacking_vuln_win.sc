if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802893" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-1964" );
	script_bugtraq_id( 54581 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-07-23 18:40:44 +0530 (Mon, 23 Jul 2012)" );
	script_name( "Mozilla Products Certificate Page Clickjacking Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49965" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027256" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027257" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-54.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_seamonkey_detect_win.sc", "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to gain sensitive information
  or bypass certain security restrictions." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.10
  Thunderbird version 5.0 through 12.0
  Mozilla Firefox version 4.x through 12.0
  Thunderbird ESR version 10.x before 10.0.6
  Mozilla Firefox ESR version 10.x before 10.0.6 on Windows" );
	script_tag( name: "insight", value: "The certificate warning functionality in
  browser/components/certerror/content/aboutCertError.xhtml fails to handle
  attempted clickjacking of the 'about:certerror' page, allowing
  man-in-the-middle attackers to trick users into adding an unintended
  exception via an IFRAME element" );
	script_tag( name: "summary", value: "This host is installed with Mozilla firefox/thunderbird/seamonkey and is
  prone to clickjacking vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 14.0 or ESR version 10.0.6 or later, upgrade to SeaMonkey version to 2.11 or later,
  upgrade to Thunderbird version to 14.0 or ESR 10.0.6 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Win/Ver" );
if(vers){
	if(version_in_range( version: vers, test_version: "4.0", test_version2: "10.0.5" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "12.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vers = get_kb_item( "Seamonkey/Win/Ver" );
if(vers){
	if(version_is_less( version: vers, test_version: "2.10" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/Win/Ver" );
if(vers){
	if(version_in_range( version: vers, test_version: "5.0", test_version2: "10.0.5" ) || version_in_range( version: vers, test_version: "11.0", test_version2: "12.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

