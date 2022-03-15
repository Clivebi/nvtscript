if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804700" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-06-18 12:25:39 +0530 (Wed, 18 Jun 2014)" );
	script_name( "Assesi 'bg' Parameter SQL Injection vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Assesi and is prone to SQL injection
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET request and check whether it is
  possible to execute sql query or not." );
	script_tag( name: "insight", value: "Flaw is due to the vereadores.php script not properly sanitizing user-supplied
  input to the 'bg' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to inject or manipulate SQL
  queries in the back-end database, allowing for the manipulation or disclosure
  of arbitrary data." );
	script_tag( name: "affected", value: "Assesi CMS" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2014060003" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/126877" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/assesi-sql-injection" );
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
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/assesi", "/cms", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(ContainsString( rcvRes, ">Assesi" )){
		url = dir + "/vereadores.php?bg='SQL-Injection-Test";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "You have an error in your SQL syntax.*SQL-Injection-Test" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

