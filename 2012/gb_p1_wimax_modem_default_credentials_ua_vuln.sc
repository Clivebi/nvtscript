if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802476" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-10-15 15:53:36 +0530 (Mon, 15 Oct 2012)" );
	script_name( "P1 WiMAX Modem Default Credentials Unauthorized Access Vulnerability" );
	script_xref( name: "URL", value: "http://pastebin.com/pkuNfSJF" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2012/Oct/99" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaw is due to the default configuration of the modem allows
  anyone to access port 80 from the internet and modem is using the same
  default login with 'admin' as the username and 'admin123' as the password." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host has P1 WiMAX Modem and is prone default credentials
  unauthorized access vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to login
  with default credentials and gain access to modem." );
	script_tag( name: "affected", value: "P1 WiMAX Modem" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
res = http_get_cache( item: "/login.php", port: port );
if(IsMatchRegexp( res, "HTTP/[0-9]\\.[0-9] 200 .*" ) && ContainsString( res, "Server: lighttpd" ) && ContainsString( res, "UI_ADMIN_USERNAME" ) && ContainsString( res, "UI_ADMIN_PASSWORD" )){
	postdata = "UI_ADMIN_USERNAME=admin&UI_ADMIN_PASSWORD=admin123";
	req = NASLString( "POST /ajax.cgi?action=login HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "HTTP/[0-9]\\.[0-9] 200 .*" ) && ContainsString( res, "location.href='index.php?sid=" ) && !ContainsString( res, "Login Fail:" )){
		security_message( port: port );
	}
}

