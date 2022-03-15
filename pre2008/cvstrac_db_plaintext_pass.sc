CPE = "cpe:/a:cvstrac:cvstrac";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14285" );
	script_version( "$Revision: 13975 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_xref( name: "OSVDB", value: "8641" );
	script_name( "CVSTrac database plaintext password storage" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "cvstrac_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "cvstrac/detected" );
	script_tag( name: "solution", value: "Update to version 1.1.4 or disable this CGI suite." );
	script_tag( name: "summary", value: "The remote host seems to be running cvstrac,
  a web-based bug and patch-set tracking system for CVS.

  This version contains a flaw related to *.db files that
  may allow an attacker to gain access to plaintext passwords." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(ereg( pattern: "^(0\\..*|1\\.0\\.[0-5]([^0-9]|$))", string: vers )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.1.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

