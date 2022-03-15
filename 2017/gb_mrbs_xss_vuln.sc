CPE = "cpe:/a:john_beranek:meeting_room_booking_system";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107264" );
	script_version( "$Revision: 11982 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-11-21 07:28:01 +0200 (Tue, 21 Nov 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Meeting Room Booking System Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_mrbs_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "MRBS/installed" );
	script_xref( name: "URL", value: "https://www.cert-bund.de/advisoryshort/CB-K17-1995" );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code in the browser
  of an unsuspecting user in the context of the affected site. This may let the
  attacker steal cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "Meeting Room Booking System prior to 1.7.0" );
	script_tag( name: "solution", value: "Upgrade to Meeting Room Booking System 1.7.0 or later." );
	script_tag( name: "summary", value: "This host is installed with Meeting Room Booking System and is
  prone to multiple vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://mrbs.sourceforge.net/download.php" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "1.7.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.7.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

