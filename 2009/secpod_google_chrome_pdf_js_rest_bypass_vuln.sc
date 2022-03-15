if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900707" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1598" );
	script_name( "Google Chrome PDF Javascript Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/503183/100/0/threaded" );
	script_xref( name: "URL", value: "http://secniche.org/papers/SNS_09_03_PDF_Silent_Form_Re_Purp_Attack.pdf" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "affected", value: "Google Chrome versions 1.0.154.65 and prior and 2.0.180.0 and prior." );
	script_tag( name: "insight", value: "An error in Adobe Acrobat JavaScript protocol handler in the context of browser
  when a PDF file is opened in it via execute DOM calls in response to a
  javascript: URI." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 4.1.249.1064 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to PDF
  Javascript Security Bypass Vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will let attacker to execute arbitrary code result in
  spoof URLs, bypass the security restriction, XSS, Memory corruption, phishing
  attacks and steal generic information from website." );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(chromeVer == NULL){
	exit( 0 );
}
if(version_in_range( version: chromeVer, test_version: "2.0", test_version2: "2.0.180.0" ) || version_is_less_equal( version: chromeVer, test_version: "1.0.154.65" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
exit( 99 );

