if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801518" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-10-05 07:29:45 +0200 (Tue, 05 Oct 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-3688" );
	script_name( "NetArtMedia WebSiteAdmin Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://vul.hackerjournals.com/?p=12826" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/398140.php" );
	script_xref( name: "URL", value: "http://pridels-team.blogspot.com/2010/09/netartmedia-real-estate-portal-v20-xss.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaw exists due to input passed via the 'lng' parameter to
  'ADMIN/login.php' is not properly validating before returning to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running NetArtMedia WebSiteAdmin and is prone to
  directory traversal vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to include and
  execute arbitrary local files via directory traversal sequences in the long parameter." );
	script_tag( name: "affected", value: "NetArtMedia WebSiteAdmin version 2.1" );
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
for dir in nasl_make_list_unique( "/websiteadmin", "/WebSiteAdmin", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, ">NetArt" ) && ContainsString( res, ">WebSiteAdmin<" )){
		req = http_get( item: NASLString( dir, "/ADMIN/login.php?lng=../../" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, ": failed to open stream:" ) && ContainsString( res, "No such file or directory" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

