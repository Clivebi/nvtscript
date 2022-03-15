if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802155" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)" );
	script_bugtraq_id( 49457 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Advanced Image Hosting Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/69609" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/104799/aihimgid-xss.txt" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site." );
	script_tag( name: "affected", value: "Advanced Image Hosting version 2.3." );
	script_tag( name: "insight", value: "The flaw is due to failure in the 'report.php' script to
  properly sanitize user supplied input in 'img_id' parameter." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Advanced Image Hosting and is prone to
  cross site scripting vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
for dir in nasl_make_list_unique( "/aihspro", "/aih", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(ContainsString( res, "Powered by:" ) && ContainsString( res, ">AIH" )){
		url = NASLString( dir, "/report.php?img_id=\"><script>alert(document.cookie)</script>" );
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "\"><script>alert(document.cookie)</script>" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}

