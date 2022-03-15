if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800431" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-01-20 08:21:11 +0100 (Wed, 20 Jan 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-0315" );
	script_name( "Google Chrome Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/389797.php" );
	script_xref( name: "URL", value: "http://nomoreroot.blogspot.com/2010/01/little-bug-in-safari-and-google-chrome.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary code, bypass
  security restrictions, sensitive information disclosure, and can cause other
  attacks." );
	script_tag( name: "affected", value: "Google Chrome version 4.0.288.1 and prior on Windows." );
	script_tag( name: "insight", value: "The flaws exist due to error in 'HREF' attribute of a stylesheet 'LINK'
  element, when reading the 'document.styleSheets[0].href' property value." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 4.0.249.89 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Google Chrome Web Browser and is prone to
  multiple vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
gcVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!gcVer){
	exit( 0 );
}
if(version_is_less_equal( version: gcVer, test_version: "4.0.288.1" )){
	report = report_fixed_ver( installed_version: gcVer, vulnerable_range: "Less than or equal to 4.0.288.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

