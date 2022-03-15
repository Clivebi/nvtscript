if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103257" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-09-15 12:51:05 +0200 (Thu, 15 Sep 2011)" );
	script_bugtraq_id( 49623 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Support Incident Tracker (SiT!) Multiple Input Validation Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49623" );
	script_xref( name: "URL", value: "https://www.htbridge.ch/advisory/multiple_vulnerabilities_in_sit_support_incident_tracker.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/519636" );
	script_xref( name: "URL", value: "http://sitracker.org/wiki/ReleaseNotes365" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "support_incident_tracker_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "sit/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more details." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Support Incident Tracker (SiT!) is prone to the following input-
  validation vulnerabilities:

  1. Multiple cross-site scripting vulnerabilities

  2. Multiple SQL-injection vulnerabilities

  3. Multiple cross-site request-forgery vulnerabilities" );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to execute arbitrary
  code, steal cookie-based authentication credentials, compromise the
  application, access or modify data, or exploit latent vulnerabilities
  in the underlying database." );
	script_tag( name: "affected", value: "Support Incident Tracker (SiT!) 3.64 is vulnerable. Other versions may
  also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!dir = get_dir_from_kb( port: port, app: "support_incident_tracker" )){
	exit( 0 );
}
url = NASLString( dir, "/portal/kb.php?start=%27" );
if(http_vuln_check( port: port, url: url, pattern: "You have an error in your SQL syntax" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

