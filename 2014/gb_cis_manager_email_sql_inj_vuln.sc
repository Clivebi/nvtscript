if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804455" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-3749" );
	script_bugtraq_id( 67442 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-05-26 16:44:36 +0530 (Mon, 26 May 2014)" );
	script_name( "CIS Manager 'email' Parameter SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with CIS Manager and is prone to SQL injection
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
  SQL injection error." );
	script_tag( name: "insight", value: "The flaw is due to the /autenticar/lembrarlogin.asp script not properly
  sanitizing user-supplied input to the 'email' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to inject or manipulate SQL
  queries in the back-end database, allowing for the manipulation or disclosure
  of arbitrary data." );
	script_tag( name: "affected", value: "CIS Manager CMS" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/93252" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2014/May/73" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
http_port = http_get_port( default: 80 );
if(!http_can_host_asp( port: http_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/autenticar", "/cismanager", "/site", "/construtiva", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/login.asp" ), port: http_port );
	if(rcvRes && IsMatchRegexp( rcvRes, ">Construtiva .*Internet Software" ) || ContainsString( rcvRes, "http://www.construtiva.com.br/" )){
		if(http_vuln_check( port: http_port, url: dir + "/lembrarlogin.asp?email='", pattern: "SQL Server.*>error.*'80040e14'" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

