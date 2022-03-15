if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111093" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-04-06 07:12:12 +0200 (Wed, 06 Apr 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Apache Axis Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_require_ports( "Services/www", 8080 );
	script_tag( name: "summary", value: "This host is running the Apache Axis SOAP stack." );
	script_xref( name: "URL", value: "https://axis.apache.org/axis/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 8080 );
for dir in nasl_make_list_unique( "/axis", "/imcws", "/WebServiceImpl", "/dswsbobje", "/ws", http_cgi_dirs( port: port ) ) {
	found = FALSE;
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	if(dir == "/services"){
		continue;
	}
	url = dir + "/services/Version?method=getVersion";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req );
	url2 = dir + "/services/non-existent";
	req2 = http_get( item: url2, port: port );
	buf2 = http_keepalive_send_recv( port: port, data: req2 );
	url3 = dir + "/index.jsp";
	buf3 = http_get_cache( item: url3, port: port );
	if( ContainsString( buf2, "<h2>AXIS error</h2>" ) || ContainsString( buf2, "No service is available at this URL" ) || ContainsString( buf2, "<h1>Axis HTTP Servlet</h1>" ) ){
		conclUrl = http_report_vuln_url( url: url2, port: port, url_only: TRUE );
		found = TRUE;
	}
	else {
		if( ContainsString( buf, "Apache Axis version:" ) || ContainsString( buf, "The AXIS engine could not find a target service to invoke!" ) || ContainsString( buf, "<h1>Axis HTTP Servlet</h1>" ) ){
			conclUrl = http_report_vuln_url( url: url, port: port, url_only: TRUE );
			found = TRUE;
		}
		else {
			if(ContainsString( buf3, "<title>Apache-Axis</title>" ) || ContainsString( buf3, "Apache-AXIS</h1>" )){
				conclUrl = http_report_vuln_url( url: url3, port: port, url_only: TRUE );
				found = TRUE;
			}
		}
	}
	if(found){
		version = "unknown";
		ver = eregmatch( string: buf, pattern: "Apache Axis version: ([0-9.]+)" );
		if(!isnull( ver[1] )){
			version = ver[1];
			conclUrl = http_report_vuln_url( url: url, port: port, url_only: TRUE );
		}
		url = dir + "/servlet/AxisServlet";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( buf, "<h2>And now... Some Services</h2>" )){
			extra += http_report_vuln_url( url: url, port: port, url_only: TRUE ) + " lists available web services\n";
		}
		url = dir + "/services";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( buf, "<h2>And now... Some Services</h2>" )){
			extra += http_report_vuln_url( url: url, port: port, url_only: TRUE ) + " lists available web services\n";
		}
		url = dir + "/happyaxis.jsp";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( buf, "<title>Axis Happiness Page</title>" ) || ContainsString( buf, "Examining webapp configuration" )){
			extra += http_report_vuln_url( url: url, port: port, url_only: TRUE ) + " exposes the system configuration\n";
		}
		url = dir + "/services/AdminService?wsdl";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( buf, "AdminServiceResponse" ) || ContainsString( buf, "AdminServiceRequest" )){
			extra += http_report_vuln_url( url: url, port: port, url_only: TRUE ) + " exposes the AdminService\n";
			if(version == "unknown"){
				ver = eregmatch( string: buf, pattern: "Apache Axis version: ([0-9.]+)" );
				if(!isnull( ver[1] )){
					version = ver[1];
					conclUrl = http_report_vuln_url( url: url, port: port, url_only: TRUE );
				}
			}
		}
		url = dir + "/EchoHeaders.jws?wsdl";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( buf, "whoamiResponse" ) || ContainsString( buf, "echoResponse" )){
			extra += http_report_vuln_url( url: url, port: port, url_only: TRUE ) + " exposes the EchoHeaders default webservice\n";
			if(version == "unknown"){
				ver = eregmatch( string: buf, pattern: "Apache Axis version: ([0-9.]+)" );
				if(!isnull( ver[1] )){
					version = ver[1];
					conclUrl = http_report_vuln_url( url: url, port: port, url_only: TRUE );
				}
			}
		}
		url = dir + "/SOAPMonitor";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( buf, "SOAPMonitorApplet.class" )){
			extra += http_report_vuln_url( url: url, port: port, url_only: TRUE ) + " expostes the SOAPMonitor Page\n";
		}
		url = dir + "/servlet/AdminServlet";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( buf, "<title>Axis</title>" ) || ContainsString( buf, "Server is running" )){
			extra += http_report_vuln_url( url: url, port: port, url_only: TRUE ) + " exposes the AdminServlet\n";
		}
		url = dir + "/servlet/MyServlet";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( buf, "<title>Axis</title>" ) || ContainsString( buf, "Server is running" )){
			extra += http_report_vuln_url( url: url, port: port, url_only: TRUE ) + " exposes the MyServlet\n";
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/axis", value: tmp_version );
		set_kb_item( name: "axis/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "([0-9.]+)", base: "cpe:/a:apache:axis:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:apache:axis";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Apache Axis", version: version, install: install, cpe: cpe, concluded: ver[0], concludedUrl: conclUrl, extra: extra ), port: port );
	}
}
exit( 0 );

