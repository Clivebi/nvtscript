if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808183" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-07-05 13:49:16 +0530 (Tue, 05 Jul 2016)" );
	script_name( "IBM WebSphere DataPower XC10 Appliance Detection (HTTP)" );
	script_tag( name: "summary", value: "Detects the installed version of
  IBM WebSphere DataPower XC10 Appliance.

  This script sends an HTTP GET request and tries to login via default credentials
  and fetches the version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_mandatory_keys( "IBM_WebSphere/banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("smtp_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( port: port );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: IBM WebSphere" )){
	exit( 0 );
}
post_data = "zeroUserName=xcadmin&zeroPassword=xcadmin&postLoginTargetURI=%2Fdashboard%2F";
req = "POST /login HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: 76\r\n" + "\r\n" + post_data;
res = http_keepalive_send_recv( port: port, data: req );
if(!ContainsString( res, "Server: IBM WebSphere" ) && IsMatchRegexp( res, "^HTTP/1\\.[01] 302" )){
	exit( 0 );
}
if(!url[0] = eregmatch( pattern: "Pzcsrf=([0-9a-zA-Z]+)", string: res )){
	exit( 0 );
}
if(!cookie[1] = eregmatch( pattern: "zsessionid=([0-9a-zA-Z]+);", string: res )){
	exit( 0 );
}
if(!cookie1[1] = eregmatch( pattern: "pzerocsrfprotectsec=(.*)==;", string: res )){
	exit( 0 );
}
url = "/dashboard/welcome/?" + url[0];
req2 = "GET " + url + " HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Cookie: zsessionid=" + cookie[1] + "; pzerocsrfprotectsec=" + cookie1[1] + "\r\n" + "\r\n";
res2 = http_keepalive_send_recv( port: port, data: req2 );
if(ContainsString( res2, ">IBM WebSphere DataPower XC10 Appliance<" ) && IsMatchRegexp( res2, "^HTTP/1\\.[01] 200" ) && ContainsString( res2, ">Dynamic Cache<" ) && ContainsString( res2, ">Simple Data Grid<" ) && ContainsString( res2, ">Log Out" )){
	version = "unknown";
	vers = eregmatch( pattern: "> ([0-9.]+).*VMware Virtual Platform <", string: res2 );
	if(vers[1]){
		version = vers[1];
	}
	set_kb_item( name: "IBM/Websphere/Datapower/XC10/Version", value: version );
	set_kb_item( name: "IBM/Websphere/Datapower/XC10/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "([0-9.]+)", base: "cpe:/h:ibm:websphere_datapower_xc10_appliance:" );
	if(!cpe){
		cpe = "cpe:/h:ibm:websphere_datapower_xc10_appliance";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "IBM WebSphere DataPower XC10 Appliance", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}

