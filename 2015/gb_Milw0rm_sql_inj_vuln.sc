if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805397" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2015-4137" );
	script_bugtraq_id( 74745 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-06-02 17:26:49 +0530 (Tue, 02 Jun 2015)" );
	script_name( "Milw0rm Clone Script SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Milw0rm
  and is prone to sql injection vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not." );
	script_tag( name: "insight", value: "Flaw is due to the 'related.php' script
  not properly sanitizing user-supplied input." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "Milw0rm Clone Script 1.0." );
	script_tag( name: "solution", value: "No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "exploit" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/May/76" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/131981/Milw0rm-Clone-Script-1.0-SQL-Injection.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/milw0rm", "/milworm_script", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/" ), port: http_port );
	if(rcvRes && ContainsString( rcvRes, ">iAm[i]nE<" )){
		url = dir + "/related.php?program=1'";
		sndReq = http_get( item: url, port: http_port );
		rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
		if(rcvRes && ContainsString( rcvRes, "mysql_num_rows" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

