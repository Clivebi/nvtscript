if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103421" );
	script_bugtraq_id( 51991 );
	script_cve_id( "CVE-2012-1217" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "STHS v2 Web Portal 'team' parameter Multiple SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51991" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/73154" );
	script_xref( name: "URL", value: "http://www.simhl.net/" );
	script_xref( name: "URL", value: "http://0nto.wordpress.com/2012/02/13/sths-v2-web-portal-2-2-sql-injection-vulnerabilty/" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-02-15 11:22:27 +0100 (Wed, 15 Feb 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "STHS v2 Web Portal is prone to multiple SQL-injection vulnerabilities
  because the application fails to sufficiently sanitize user-supplied
  data before using it in an SQL query." );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "STHS v2 Web Portal 2.2 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
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
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/home.php";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "Site powered by.*SIMHL.net" )){
		url = dir + "/prospects.php?team=-1%20union%20select%20sqli_test,saf,3,4,5,6,7,8,9,10,11,12";
		if(http_vuln_check( port: port, url: url, pattern: "Unknown column 'sqli_test' in 'field list'" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

