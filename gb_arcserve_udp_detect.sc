if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105294" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-05-14T13:11:51+0000" );
	script_tag( name: "last_modification", value: "2021-05-14 13:11:51 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "creation_date", value: "2015-06-10 17:49:06 +0200 (Wed, 10 Jun 2015)" );
	script_name( "Arcserve Unified Data Protection (UDP) Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Arcserve Unified Data Protection (UDP)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8014, 8015, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
cpe = "cpe:/a:arcserve:arcserve_unified_data_protection";
port = http_get_port( default: 8014 );
host = http_host_name( port: port );
useragent = http_get_user_agent();
func check_win(  ){
	data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\">" + "<S:Body><ns2:getVersionInfo xmlns:ns2=\"http://webservice.arcflash.ca.com\" " + "xmlns:ns3=\"http://data.webservice.arcflash.ca.com/xsd\" " + "xmlns:ns4=\"http://backup.data.webservice.arcflash.ca.com/xsd\" " + "xmlns:ns5=\"http://restore.data.webservice.arcflash.ca.com/xsd\" " + "xmlns:ns6=\"http://vsphere.data.webservice.arcflash.ca.com/xsd\" " + "xmlns:ns7=\"http://browse.data.webservice.arcflash.ca.com/xsd\" " + "xmlns:ns8=\"http://remotedeploy.data.webservice.arcflash.ca.com/xsd\" " + "xmlns:ns9=\"http://catalog.data.webservice.arcflash.ca.com/xsd\" " + "xmlns:ns10=\"http://activitylog.data.webservice.arcflash.ca.com/xsd\"/>" + "</S:Body></S:Envelope>";
	len = strlen( data );
	req = "POST /WebServiceImpl/services/FlashServiceImpl HTTP/1.1\r\n" + "Accept: text/xml, multipart/related\r\n" + "Content-Type: text/xml; charset=utf-8;\r\n" + "SOAPAction: \"http://webservice.arcflash.ca.com/IFlashService_R16_5/getVersionInfoRequest\"\r\n" + "User-Agent: " + useragent + "\r\n" + "Cache-Control: no-cache\r\n" + "Pragma: no-cache\r\n" + "Host: " + host + "\r\n" + "Connection: close\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + data;
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!ContainsString( buf, "arcserve" ) || !ContainsString( buf, "getVersionInfoResponse" ) || !ContainsString( buf, "buildNumber" ) || !ContainsString( buf, "majorVersion>" )){
		return;
	}
	set_kb_item( name: "arcserve_udp/detected", value: TRUE );
	set_kb_item( name: "arcserve_udp/soap_typ", value: "windows" );
	set_kb_item( name: "arcserve_udp/soap_raw_response", value: buf );
	lines = split( buffer: buf, sep: "><", keep: FALSE );
	for line in lines {
		if( ContainsString( line, "majorVersion>" ) ){
			major_version = eregmatch( pattern: "majorVersion>([^<]+)<", string: line );
			if(!isnull( major_version[1] )){
				major = major_version[1];
				concluded += "\n" + major_version[0];
			}
		}
		else {
			if( ContainsString( line, "minorVersion" ) ){
				minor_version = eregmatch( pattern: "minorVersion>([^<]+)<", string: line );
				if(!isnull( minor_version[1] )){
					minor = minor_version[1];
					concluded += "\n" + minor_version[0];
				}
			}
			else {
				if( ContainsString( line, "buildNumber>" ) ){
					build_number = eregmatch( pattern: "buildNumber>([^<]+)<", string: line );
					if(!isnull( build_number[1] )){
						build = build_number[1];
						set_kb_item( name: "arcserve_udp/build", value: build );
						concluded += "\n" + build_number[0];
					}
				}
				else {
					if(ContainsString( line, "updateNumber>" )){
						update_number = eregmatch( pattern: "updateNumber>([^<]+)<", string: line );
						if(!isnull( update_number[1] )){
							update = update_number[1];
							set_kb_item( name: "arcserve_udp/update", value: update );
							concluded += "\n" + update_number[0];
						}
					}
				}
			}
		}
	}
	vers = "unknown";
	if(!isnull( major )){
		vers = major;
	}
	if( !isnull( minor ) ) {
		vers += "." + minor;
	}
	else {
		vers += ".0";
	}
	if(vers != "unknown"){
		cpe += ":" + vers;
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Arcserve Unified Data Protection (UDP)", version: vers + " (" + build + ")", install: "/", cpe: cpe, concluded: concluded ), port: port );
	exit( 0 );
}
func check_lin(  ){
	data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\">" + "<S:Body><ns2:getVersionInfo xmlns:ns2=\"http://webservice.linuximaging.arcserve.ca.com\" " + "xmlns:ns3=\"http://backup.data.webservice.arcflash.ca.com/xsd\" " + "xmlns:ns4=\"http://catalog.data.webservice.arcflash.ca.com/xsd\" " + "xmlns:ns5=\"http://browse.data.webservice.arcflash.ca.com/xsd\"/>" + "</S:Body></S:Envelope>";
	len = strlen( data );
	req = "POST /WebServiceImpl/services/LinuximagingServiceImpl HTTP/1.1\r\n" + "Accept: text/xml, multipart/related\r\n" + "Content-Type: text/xml; charset=utf-8\r\n" + "SOAPAction: \"http://webservice.linuximaging.arcserve.ca.com/ILinuximagingService/getVersionInfoRequest\"\r\n" + "User-Agent: " + useragent + "\r\n" + "Cache-Control: no-cache\r\n" + "Pragma: no-cache\r\n" + "Host: " + host + "\r\n" + "Connection: close\r\n" + "Content-Length: " + len + "\r\n" + "\r\n" + data;
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!ContainsString( buf, "arcserve" ) || !ContainsString( buf, "getVersionInfoResponse" ) || !ContainsString( buf, "buildNumber" ) || !ContainsString( buf, "version>" )){
		return;
	}
	set_kb_item( name: "arcserve_udp/detected", value: TRUE );
	set_kb_item( name: "arcserve_udp/soap_typ", value: "linux" );
	set_kb_item( name: "arcserve_udp/soap_raw_response", value: buf );
	lines = split( buffer: buf, sep: "><", keep: FALSE );
	vers = "unknown";
	build = "unknown";
	for line in lines {
		if(ContainsString( line, "version>" )){
			version = eregmatch( pattern: "version>([^<]+)</version", string: line );
			if(!isnull( version[1] )){
				vers = version[1];
				cpe += ":" + vers;
				concluded += "\n" + version[0];
			}
		}
		if(ContainsString( line, "buildNumber>" )){
			build_number = eregmatch( pattern: "buildNumber>([^<]+)</buildNumber", string: line );
			if(!isnull( build_number[1] )){
				build = build_number[1];
				set_kb_item( name: "arcserve_udp/build", value: build );
				concluded += "\n" + build_number[0];
			}
		}
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Arcserve Unified Data Protection (UDP)", version: vers + " (" + build + ")", install: "/", cpe: cpe, concluded: concluded ), port: port );
	exit( 0 );
}
res = http_get_cache( port: port, item: "/management/" );
if( IsMatchRegexp( res, "^HTTP/1\\.[01] 302" ) && ContainsString( res, "/samlsso?SAMLRequest=" ) ){
	url = eregmatch( pattern: "(/samlsso\\?SAMLRequest=.*%3D)", string: res );
	if(isnull( url[1] )){
		exit( 0 );
	}
	req = http_get( port: port, item: url[1] );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!cookie = http_get_cookie_from_header( buf: res, pattern: "(JSESSIONID=[^;]+)" )){
		exit( 0 );
	}
	url = eregmatch( pattern: "(/commonauth\\?sessionDataKey=.*samlsso)", string: res );
	if(isnull( url[1] )){
		exit( 0 );
	}
	headers = make_array( "Cookie", cookie );
	req = http_get_req( port: port, url: url[1], add_headers: headers );
	res = http_keepalive_send_recv( port: port, data: req );
	url = eregmatch( pattern: "(/authenticationendpoint[^\r\n]+)", string: res );
	if(isnull( url[1] )){
		exit( 0 );
	}
	req = http_get_req( port: port, url: url[1], add_headers: headers );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!ContainsString( res, "<title>Arcserve Unified Data Protection</title>" )){
		exit( 0 );
	}
	version = "unknown";
	set_kb_item( name: "arcserve_udp/detected", value: TRUE );
	vers = eregmatch( pattern: "<label class=\"login_copyright\"[^>]+>version ([0-9.]+)<", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	update = eregmatch( pattern: "<label class=\"login_copyright\">update ([0-9]+) build ([0-9]+)<", string: res );
	if(!isnull( update[1] )){
		set_kb_item( name: "arcserve_udp/update", value: update[1] );
		extra += "Update:   " + update[1] + "\n";
	}
	if(!isnull( update[2] )){
		set_kb_item( name: "arcserve_udp/build", value: update[2] );
		extra += "Build:    " + update[2] + "\n";
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:arcserve:arcserve_unified_data_protection:" );
	if(!cpe){
		cpe = "cpe:/a:arcserve:arcserve_unified_data_protection";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Arcserve Unified Data Protection (UDP)", version: version, install: "/", cpe: cpe, concluded: vers[0], extra: extra ), port: port );
	exit( 0 );
}
else {
	url = "/";
	buf = http_get_cache( item: url, port: port );
	if(!ContainsString( tolower( buf ), "arcserve" )){
		exit( 0 );
	}
	check_win();
	check_lin();
}
exit( 0 );

