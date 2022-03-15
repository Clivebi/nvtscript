if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804179" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-12-27 13:57:37 +0530 (Fri, 27 Dec 2013)" );
	script_name( "Zen-cart Database Backup Disclosure Vulnerability" );
	script_tag( name: "summary", value: "The host is running Zen-cart and is prone to database backup disclosure
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is vulnerable
  or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "insight", value: "The flaw is due to unspecified error that allows unauthenticated access to
  database backup" );
	script_tag( name: "affected", value: "Zen-cart version 1.5.1 and probably prior" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to obtain sensitive
  database information by downloading the database backup." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2013120167" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/zen-cart-database-backup-disclosure" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
zcPort = http_get_port( default: 80 );
if(!http_can_host_php( port: zcPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/zencart", "/zen-cart", "/cart", http_cgi_dirs( port: zcPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: zcPort );
	if(res && ( egrep( pattern: "Powered by.*Zen Cart<", string: res ) )){
		url = dir + "/zc_install/sql/mysql_zencart.sql";
		if(http_vuln_check( port: zcPort, url: url, pattern: "Zen Cart SQL Load", extra_check: make_list( "customers_id",
			 "admin_name" ) )){
			security_message( port: zcPort );
			exit( 0 );
		}
	}
}
exit( 99 );

