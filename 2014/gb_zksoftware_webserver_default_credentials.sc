if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804475" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-07-21 12:35:29 +0530 (Mon, 21 Jul 2014)" );
	script_name( "ZKSoftware WebServer Default Admin Credentials" );
	script_tag( name: "summary", value: "This host is running ZKSoftware WebServer and it has default admin
  credentials." );
	script_tag( name: "vuldetect", value: "Send a crafted default admin credentials via HTTP POST request and check
  whether it is possible to login or not." );
	script_tag( name: "insight", value: "It was possible to login with default credentials." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to gain access to sensitive
  information or modify system configuration." );
	script_tag( name: "affected", value: "ZKSoftware WebServer" );
	script_tag( name: "solution", value: "Change the default credentials." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_xref( name: "URL", value: "http://blog.infobytesec.com/2014/07/perverting-embedded-devices-zksoftware_2920.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_get_http_banner.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ZK_Web_Server/banner" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
kPort = http_get_port( default: 80 );
kBanner = http_get_remote_headers( port: kPort );
if(!kBanner || !ContainsString( kBanner, "Server: ZK Web Server" )){
	exit( 0 );
}
host = http_host_name( port: kPort );
postdata = "username=administrator&userpwd=123456";
zkReq = NASLString( "POST /csl/check HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n\\r\\n", postdata );
zkRes = http_keepalive_send_recv( port: kPort, data: zkReq );
if(IsMatchRegexp( zkRes, "^HTTP/1\\.[01] 200" ) && ContainsString( zkRes, ">Department Name<" ) && ContainsString( zkRes, ">Privilege<" ) && ContainsString( zkRes, ">Name<" )){
	security_message( port: kPort );
	exit( 0 );
}
exit( 99 );

