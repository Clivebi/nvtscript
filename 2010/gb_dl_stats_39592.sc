if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100591" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-21 13:10:07 +0200 (Wed, 21 Apr 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2010-1497" );
	script_bugtraq_id( 39592 );
	script_name( "dl_stats Cross Site Scripting and SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/39592" );
	script_xref( name: "URL", value: "http://dl.clausvb.de/view_file.php?id=10" );
	script_xref( name: "URL", value: "http://www.xenuser.org/2010/04/18/dl_stats-multiple-vulnerabilities-sqli-xss-unprotected-admin-panel/" );
	script_xref( name: "URL", value: "http://www.xenuser.org/documents/security/dl_stats_multiple_vulnerabilities.txt" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "dl_stats is prone to an SQL-injection vulnerability and multiple cross-
site scripting vulnerabilities.

Exploiting these issues could allow an attacker to steal cookie-based
authentication credentials, control how the site is rendered to the
user, compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database.

dl_stats 2.0 is vulnerable, other versions may also be affected." );
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
for dir in nasl_make_list_unique( "/dl_stats", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/download.php?id=2+AND+1=2+UNION+SELECT+1,2,3,4,0x53514c2d496e6a656374696f6e2d54657374--" );
	if(http_vuln_check( port: port, url: url, pattern: "SQL-Injection-Test" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

