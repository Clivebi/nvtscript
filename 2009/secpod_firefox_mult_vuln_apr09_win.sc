if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900342" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1310", "CVE-2009-1311", "CVE-2009-1312" );
	script_bugtraq_id( 34656 );
	script_name( "Mozilla Firefox Multiple Vulnerabilities Apr-09 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34758" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-14.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-16.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-17.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-18.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-19.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-20.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-21.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-22.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could result in Information Disclosure, XSS, Script
  Injection, Memory Corruption, CSRF, Arbitrary JavaScript code execution or
  can cause denial of service attacks." );
	script_tag( name: "affected", value: "Firefox version prior to 3.0.9 on Windows." );
	script_tag( name: "insight", value: "Please see the references for more information about the vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.0.9." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(!ffVer){
	exit( 0 );
}
if(version_is_less( version: ffVer, test_version: "3.0.9" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "3.0.9" );
	security_message( port: 0, data: report );
}

