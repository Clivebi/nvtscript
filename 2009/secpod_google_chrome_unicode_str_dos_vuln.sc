if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900805" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-2578" );
	script_name( "Google Chrome Unicode String Denial Of Service Vulnerability" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3338/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/505092/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation lets the attacker cause memory or CPU consumption,
  resulting in Denial of Service condition." );
	script_tag( name: "affected", value: "Google Chrome version 2.x to 2.0.172 on Windows." );
	script_tag( name: "insight", value: "Error occurs when application fails to handle user supplied input into the
  'write' method via a long Unicode string argument." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 4.1.249.1064 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to Denial of
  Service vulnerability." );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_in_range( version: chromeVer, test_version: "2.0", test_version2: "2.0.172" )){
	report = report_fixed_ver( installed_version: chromeVer, vulnerable_range: "2.0 - 2.0.172" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

