if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802891" );
	script_version( "2019-07-17T11:14:11+0000" );
	script_cve_id( "CVE-2012-1950", "CVE-2012-1965", "CVE-2012-1966" );
	script_bugtraq_id( 54580, 54578, 54586 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2012-07-23 18:31:44 +0530 (Mon, 23 Jul 2012)" );
	script_name( "Mozilla Firefox Multiple Vulnerabilities - July12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49965" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027256" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027257" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-43.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-46.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2012/mfsa2012-55.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser." );
	script_tag( name: "affected", value: "Mozilla Firefox version 4.x through 13.0
  Mozilla Firefox ESR version 10.x before 10.0.6 on Windows" );
	script_tag( name: "insight", value: "- The improper implementation of drag-and-drop feature, fails to display
    the URL properly in addressbar.

  - An error when handling 'feed:' URLs can be exploited to bypass the output
    filters and execute arbitrary JavaScript code.

  - The context-menu restrictions for data: URLs are not the same as for
    javascript: URLs, which allows to conduct XSS attacks." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 14.0 or ESR version 10.0.6 or later." );
	script_tag( name: "summary", value: "This host is installed with Mozilla firefox and is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_in_range( version: ffVer, test_version: "4.0", test_version2: "10.0.5" ) || version_in_range( version: ffVer, test_version: "11.0", test_version2: "13.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

