if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810317" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-12-23 11:51:30 +0530 (Fri, 23 Dec 2016)" );
	script_name( "Apache Hadoop Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8088, 50070 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of Apache Hadoop.

  This script sends an HTTP GET request and tries to get the version from the response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 50070 );
urls = make_array( "/dfshealth.jsp", "> *Version:( |</td>)?<td> *([0-9\\.]+)([0-9a-z.\\-]+)?,", "/dfshealth.html", "\"SoftwareVersion\" : \"([0-9.]+)([0-9a-z.\\-]+)?\",", "/cluster/cluster", "Hadoop version:\\s+(</th>\\s+)?<td>\\s+([0-9\\.]+)" );
for url in keys( urls ) {
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, ">Cluster Summary<" ) && ( ContainsString( res, "Apache Hadoop<" ) || ContainsString( res, ">Hadoop<" ) ) ) || ( ContainsString( res, "<title>Namenode information</title>" ) && ContainsString( res, ">Hadoop</div>" ) ) || ( ContainsString( res, "About the Cluster" ) && ContainsString( res, "Hadoop version" ) )){
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		install = "/";
		version = "unknown";
		extra = "";
		secureModeDisabled = FALSE;
		if( url == "/dfshealth.html" ){
			url2 = "/jmx?qry=Hadoop:service=NameNode,name=NameNodeInfo";
			req = http_get( item: url2, port: port );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
				conclUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
			}
			vers = eregmatch( pattern: urls[url], string: res );
			if(vers[1]){
				version = vers[1];
			}
			set_kb_item( name: "Apache/Hadoop/Installed", value: TRUE );
		}
		else {
			vers = eregmatch( pattern: urls[url], string: res );
			if(vers[2]){
				version = vers[2];
			}
			set_kb_item( name: "Apache/Hadoop/Installed", value: TRUE );
		}
		if( ContainsString( res, ">Security is <em>OFF</em>" ) ){
			secureModeDisabled = TRUE;
		}
		else {
			url3 = "/jmx?qry=Hadoop:service=NameNode,name=NameNodeStatus";
			req = http_get( item: url3, port: port );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "\"SecurityEnabled\" : false," )){
				secureModeDisabled = TRUE;
			}
		}
		if(secureModeDisabled){
			extra = "Secure Mode is not enabled.";
			set_kb_item( name: "Apache/Hadoop/SecureMode/Disabled", value: TRUE );
			set_kb_item( name: "Apache/Hadoop/SecureMode/" + port + "/Disabled", value: TRUE );
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:hadoop:" );
		if(!cpe){
			cpe = "cpe:/a:apache:hadoop";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Apache Hadoop", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, extra: extra, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

