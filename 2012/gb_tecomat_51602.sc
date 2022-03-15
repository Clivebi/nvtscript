if(description){
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51602" );
	script_xref( name: "URL", value: "http://dsecrg.com/pages/vul/show.php?id=407" );
	script_xref( name: "URL", value: "http://www.tecomat.com/index.php?a=cat.308" );
	script_oid( "1.3.6.1.4.1.25623.1.0.103397" );
	script_bugtraq_id( 51602 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Tecomat Foxtrot Default Password Security Bypass Vulnerability" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-01-24 10:17:53 +0100 (Tue, 24 Jan 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Tecomat Foxtrot is prone to a security-bypass vulnerability." );
	script_tag( name: "impact", value: "Successful attacks can allow an attacker to gain access to
the affected application using the default authentication
credentials." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
url = "/syswww/login.xml";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "SoftPLC" )){
	exit( 0 );
}
cookie = eregmatch( string: buf, pattern: "Set-Cookie: SoftPLC=([^;]+)" );
if(isnull( cookie[1] )){
	exit( 0 );
}
c = cookie[1];
host = get_host_name();
for(i = 9;i >= 0;i--){
	req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Connection: keep-alive\\r\\n", "Referer: http://", host, url, "\\r\\n", "Cookie: SoftPLC=", c, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: 10\\r\\n", "\\r\\n", "USER=", i, "&PASS=", i, "\\r\\n\\r\\n" );
	buf = http_keepalive_send_recv( port: port, data: req );
	search = NASLString( "Location: http://", host, "/index.xml" );
	if(egrep( string: buf, pattern: search )){
		desc = NASLString( "It was possible to login with the following credentials\\n\\nURL:User:Password\\n\\n", url, ":", i, ":", i, "\\n" );
		security_message( port: port, data: desc );
		exit( 0 );
	}
	sleep( 1 );
}

