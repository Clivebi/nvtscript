CPE = "cpe:/a:openca:openca";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14714" );
	script_version( "$Revision: 13975 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 9123 );
	script_cve_id( "CVE-2003-0960" );
	script_xref( name: "OSVDB", value: "2884" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "OpenCA multiple signature validation bypass" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_openca_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "openca/installed" );
	script_tag( name: "solution", value: "Upgrade to the newest version of this software." );
	script_tag( name: "summary", value: "The remote host seems to be running an older version of OpenCA.

  It is reported that OpenCA versions up to and including 0.9.1.3 contains
  multiple flaws that may allow revoked or expired certificates to be accepted as valid." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_is_less_equal( version: vers, test_version: "0.9.1.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "N/A" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

