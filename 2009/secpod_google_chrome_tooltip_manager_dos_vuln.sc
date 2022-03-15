if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900825" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-7061" );
	script_bugtraq_id( 30975 );
	script_name( "Google Chrome 'tooltip_manager.cc' Denial Of Service Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/45039" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/496151/100/0/threaded" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/496172/100/100/threaded" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation lets the attacker cause memory or CPU consumption,
  resulting in Denial of Service condition." );
	script_tag( name: "affected", value: "Google Chrome version prior to 0.2.149.30 on Windows." );
	script_tag( name: "insight", value: "Error occurs in tooltip manager in chrome/views/tooltip_manager.cc caused
  via a tag with a long title attribute, which is not properly handled
  when displaying a tooltip." );
	script_tag( name: "solution", value: "Upgrade to version 0.2.149.30 or later." );
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
if(version_is_less( version: chromeVer, test_version: "0.2.149.30" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "0.2.149.30" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

