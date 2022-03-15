if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802315" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ileys Web Control SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://cryptr.org/printthread.php?tid=2278" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103372/ileys-sql.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause SQL injection
  attack and gain sensitive information." );
	script_tag( name: "affected", value: "Ileys Web Control version 2.0." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  passed via the 'id' parameter in 'view.php', which allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Ileys Web Control and is prone to sql
  injection vulnerability." );
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
for dir in nasl_make_list_unique( "/", "/ileys", "/admin", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( res, "Powered by:" ) && ContainsString( res, "Ileys Web Control" )){
		url = NASLString( dir, "/view.php?id=3333\"" );
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, "You have an error in your SQL syntax;" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

