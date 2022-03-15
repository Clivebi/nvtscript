if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802342" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 40625 );
	script_cve_id( "CVE-2010-5006" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-11-09 16:19:55 +0530 (Wed, 09 Nov 2011)" );
	script_name( "EMO Realty Manager 'cat1' Parameter SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://securityreason.com/securityalert/8505" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/90411/emorealtymanager-sql.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to perform SQL
  injection attack and gain sensitive information." );
	script_tag( name: "affected", value: "EMO Realty Manager Software." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user-supplied input
  passed via the 'cat1' parameter to 'googlemap/index.php', which allows attackers
  to manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running EMO Realty Manager Software and is prone to
  SQL injection vulnerability" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
for dir in nasl_make_list_unique( "/emo_virtual", "/emorealty", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, "<title>EMO Realty Manager" )){
		url = NASLString( dir, "/googlemap/index.php?cat1='" );
		if(http_vuln_check( port: port, url: url, pattern: "You have an error" + " in your SQL syntax;", check_header: FALSE )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

