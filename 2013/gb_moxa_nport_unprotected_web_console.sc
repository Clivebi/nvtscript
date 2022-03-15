if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103664" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Moxa NPort Unprotected Web Console" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-02-19 12:01:48 +0100 (Tue, 19 Feb 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "MoxaHttp/banner" );
	script_tag( name: "solution", value: "Set a password." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "summary", value: "The remote Moxa NPort Web Console is not protected by a password." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: MoxaHttp/1.0" )){
	exit( 0 );
}
url = "/main.htm";
if(http_vuln_check( port: port, url: url, pattern: "Basic Settings", extra_check: make_list( "Model Name",
	 "MAC Address" ) )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

