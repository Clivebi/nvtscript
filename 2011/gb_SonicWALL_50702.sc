if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103342" );
	script_bugtraq_id( 50702 );
	script_cve_id( "CVE-2011-5262" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "SonicWALL Aventail 'CategoryID' Parameter SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50702" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-11-21 09:56:06 +0100 (Mon, 21 Nov 2011)" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "SonicWALL Aventail is prone to an SQL-injection vulnerability because
  the application fails to properly sanitize user-supplied input before using it in an SQL query." );
	script_tag( name: "impact", value: "A successful exploit may allow an attacker to compromise the
  application, access or modify data, or exploit vulnerabilities in the underlying database.

  Further research conducted by the vendor indicates this issue may not
  be a vulnerability affecting the application." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
vt_strings = get_vt_strings();
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = NASLString( dir, "/prodpage.cfm?CFID=&CFTOKEN=&CategoryID='", vt_strings["lowercase"] );
	if(http_vuln_check( port: port, url: url, pattern: "ODBC Error", extra_check: "AND Products.CategoryID = ''" + vt_strings["lowercase"] )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

