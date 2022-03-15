if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103250" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-12 14:00:02 +0200 (Mon, 12 Sep 2011)" );
	script_bugtraq_id( 49540 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "MYRE Real Estate Software 'findagent.php' Cross Site Scripting and SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49540" );
	script_xref( name: "URL", value: "http://secpod.org/advisories/SECPOD_MRS_SQL_XSS_Vuln.txt" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "MYRE Real Estate Software is prone to an SQL-injection and multiple
  cross-site scripting vulnerabilities." );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to steal cookie-
  based authentication credentials, compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database." );
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
if(!http_can_host_php( port: port )){
	exit( 0 );
}
vt_strings = get_vt_strings();
for dir in nasl_make_list_unique( "/realestate", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) || !ContainsString( buf, ">Powered by MYRE Realty Manager<" )){
		continue;
	}
	url = NASLString( dir, "/findagent.php?country1=%3Cscript%3Ealert(/", vt_strings["lowercase"], "/)%3C/script%3E" );
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/" + vt_strings["lowercase"] + "/\\)</script>", extra_check: "MYRE Real Estate Software", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

