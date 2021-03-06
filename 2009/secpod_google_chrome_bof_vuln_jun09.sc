if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900380" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-2121" );
	script_bugtraq_id( 35462 );
	script_name( "Google Chrome Web Script Execution Vulnerabilities - Jun09" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35548" );
	script_xref( name: "URL", value: "http://code.google.com/p/chromium/issues/detail?id=14508" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2009/06/stable-beta-update-security-fix.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code, and
  can cause Denial of Service or compromise a user's system." );
	script_tag( name: "affected", value: "Google Chrome version prior to 2.0.172.33 on Windows." );
	script_tag( name: "insight", value: "The flaw is due to an error when handling unspecified HTTP responses.
  This can be exploited to cause a buffer overflow via a specially crafted HTTP
  response received from an HTTP server." );
	script_tag( name: "solution", value: "Upgrade to version 2.0.172.33 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host has Google Chrome installed and is prone to buffer
  overflow vulnerability." );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "2.0.172.33" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "2.0.172.33" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

