CPE = "cpe:/a:lighttpd:lighttpd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100212" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-05-28 16:49:18 +0200 (Thu, 28 May 2009)" );
	script_bugtraq_id( 35097 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Lighttpd Trailing Slash Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "sw_lighttpd_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "lighttpd/installed" );
	script_tag( name: "solution", value: "Update to version 1.4.24 or later." );
	script_tag( name: "summary", value: "According to its version number, the remote version of Lighttpd is
  prone to an information-disclosure vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to obtain sensitive information
  that may lead to further attacks." );
	script_tag( name: "affected", value: "Lighttpd 1.4.23 is vulnerable. Other versions may also be affected." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/35097" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://www.lighttpd.net" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "1.4.23" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.4.24" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

