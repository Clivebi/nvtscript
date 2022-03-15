if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14249" );
	script_version( "2020-04-27T11:01:03+0000" );
	script_bugtraq_id( 7430 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-04-27 11:01:03 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_name( "Opera web browser news url denial of service vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Windows" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "summary", value: "The remote host is using Opera - an alternative web browser.

  This version reportedly occurs when processing a 'news:' URL
  of excessive length, that may result in a denial of service.
  It has been reported that this issue will trigger a condition
  that will prevent Opera from functioning until the program
  has been reinstalled." );
	script_tag( name: "solution", value: "Install Opera 7.20 or newer." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
OperaVer = get_kb_item( "Opera/Win/Version" );
if(!OperaVer){
	exit( 0 );
}
if(version_is_less_equal( version: OperaVer, test_version: "7.19" )){
	report = report_fixed_ver( installed_version: OperaVer, vulnerable_range: "Less than or equal to 7.19" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

