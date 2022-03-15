if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14244" );
	script_version( "2020-04-27T11:01:03+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 11:01:03 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-2260" );
	script_bugtraq_id( 10337 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "Opera web browser address bar spoofing weakness" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Windows" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "solution", value: "Install Opera 7.50 or newer." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The remote host is using Opera - an alternative web browser.

  This version of Opera is vulnerable to a security weakness
  that may permit malicious web pages to spoof address bar information.

  This is reportedly possible through malicious use of the
  JavaScript 'unOnload' event handler when the browser
  is redirected to another page.

  This issue could be exploited to spoof the domain of a malicious web page,
  potentially causing the victim user to trust the spoofed domain." );
	exit( 0 );
}
require("version_func.inc.sc");
OperaVer = get_kb_item( "Opera/Win/Version" );
if(!OperaVer){
	exit( 0 );
}
if(version_is_less_equal( version: OperaVer, test_version: "7.49" )){
	report = report_fixed_ver( installed_version: OperaVer, vulnerable_range: "Less than or equal to 7.49" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

