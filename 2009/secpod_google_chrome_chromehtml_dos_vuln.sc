if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900833" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-2974" );
	script_name( "Google Chrome 'chromehtml: URI' Denial Of Service Vulnerability" );
	script_xref( name: "URL", value: "http://websecurity.com.ua/3435/" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2009-08/0236.html" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2009-08/0217.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful attacks could allows remote attackers to cause application hang
  and CPU consumption which may result in Denial of Service condition." );
	script_tag( name: "affected", value: "Google Chrome version 1.0.154.65 and prior on Windows." );
	script_tag( name: "insight", value: "Error occurs when vectors involving a series of function calls that set a
  'chromehtml:' URI value for the document.location property." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 4.1.249.1064 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to Denial
  of Service vulnerability." );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(isnull( chromeVer )){
	exit( 0 );
}
if(version_is_less_equal( version: chromeVer, test_version: "1.0.154.65" )){
	report = report_fixed_ver( installed_version: chromeVer, vulnerable_range: "Less than or equal to 1.0.154.65" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

