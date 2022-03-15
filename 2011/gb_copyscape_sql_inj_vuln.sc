if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802122" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-07-18 15:23:56 +0200 (Mon, 18 Jul 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Copyscape SQL Injection Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/102970/copyscape-sql.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to manipulate SQL
  queries by injecting arbitrary SQL code or obtain sensitive information." );
	script_tag( name: "affected", value: "Copyscape" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied
  input via 'ID' parameter in 'ancillary.asp', which allows attackers to
  manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Copyscape and is prone to SQL injection
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/Copyscape", "/store", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/", port: port );
	if(ContainsString( res, "web site content infringement by Copyscape\"" )){
		url = NASLString( dir, "/ancillary.asp?ID=54'" );
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, ">Microsoft JET Database Engine<" ) && ContainsString( res, ">Syntax error in string in query" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

