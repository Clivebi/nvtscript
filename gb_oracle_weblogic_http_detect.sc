if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100493" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-03-16T06:01:36+0000" );
	script_tag( name: "last_modification", value: "2021-03-16 06:01:36 +0000 (Tue, 16 Mar 2021)" );
	script_tag( name: "creation_date", value: "2010-02-14 12:35:00 +0100 (Sun, 14 Feb 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Oracle WebLogic Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 7001 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Oracle WebLogic Server.

  The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_xref( name: "URL", value: "https://www.oracle.com/middleware/weblogic/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 7001 );
banner = http_get_remote_headers( port: port );
version = "unknown";
servicepack = "unknown";
if( IsMatchRegexp( banner, "Server: WebLogic " ) ){
	vers = eregmatch( pattern: "WebLogic (Server )?([0-9.]+)( (SP|Service Pack )([0-9]+))?", string: banner, icase: TRUE );
	if(!isnull( vers[2] )){
		version = vers[2];
		set_kb_item( name: "oracle/weblogic/http/" + port + "/concluded", value: vers[0] );
		url = "/";
		if(!isnull( vers[5] )){
			servicepack = vers[5];
		}
	}
}
else {
	url = "/console/login/LoginForm.jsp";
	buf = http_get_cache( item: url, port: port );
	if( buf && ( IsMatchRegexp( buf, "<title>(Oracle|BEA) WebLogic Server Administration Console" ) || egrep( pattern: "<TITLE>WebLogic Server.*Console Login", string: buf ) ) ){
		vers = eregmatch( string: buf, pattern: "WebLogic Server ([0-9.]+)", icase: TRUE );
		if( !isnull( vers[1] ) ){
			version = vers[1];
			set_kb_item( name: "oracle/weblogic/http/" + port + "/concluded", value: vers[0] );
		}
		else {
			vers = eregmatch( string: buf, pattern: "WebLogic Server Version: ([0-9.]+)", icase: TRUE );
			if(!isnull( vers[1] )){
				version = vers[1];
				set_kb_item( name: "oracle/weblogic/http/" + port + "/concluded", value: vers[0] );
			}
		}
	}
	else {
		exit( 0 );
	}
}
endpoints = make_array( "/_async/AsyncResponseService?WSDL", "www\\.bea\\.com/async/AsyncResponseService", "/_async/AsyncResponseServiceHttps?WSDL", "www\\.bea\\.com/async/AsyncResponseService", "/_async/AsyncResponseServiceJms?WSDL", "www\\.bea\\.com/async/AsyncResponseService", "/_async/AsyncResponseServiceSoap12?WSDL", "www\\.bea\\.com/async/AsyncResponseService", "/_async/AsyncResponseServiceSoap12Https?WSDL", "www\\.bea\\.com/async/AsyncResponseService", "/_async/AsyncResponseServiceSoap12Jms?WSDL", "www\\.bea\\.com/async/AsyncResponseService", "/wls-wsat/CoordinatorPortType", "weblogic\\.wsee\\.wstx\\.wsat\\.v1[01]\\.endpoint\\.CoordinatorPort", "/wls-wsat/CoordinatorPortType11", "weblogic\\.wsee\\.wstx\\.wsat\\.v1[01]\\.endpoint\\.CoordinatorPort", "/wls-wsat/ParticipantPortType", "weblogic\\.wsee\\.wstx\\.wsat\\.v1[01]\\.endpoint\\.ParticipantPort", "/wls-wsat/ParticipantPortType11", "weblogic\\.wsee\\.wstx\\.wsat\\.v1[01]\\.endpoint\\.ParticipantPort", "/wls-wsat/RegistrationPortTypeRPC", "weblogic\\.wsee\\.wstx\\.wsc\\.v1[01]\\.endpoint\\.RegistrationPort", "/wls-wsat/RegistrationRequesterPortType", "weblogic\\.wsee\\.wstx\\.wsc\\.v1[01]\\.endpoint\\.RegistrationRequesterPort", "/wls-wsat/RegistrationPortTypeRPC11", "weblogic\\.wsee\\.wstx\\.wsc\\.v1[01]\\.endpoint\\.RegistrationPort" );
for endpoint in keys( endpoints ) {
	check = endpoints[endpoint];
	req = http_get( port: port, item: endpoint );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(res && eregmatch( string: res, pattern: check, icase: FALSE )){
		set_kb_item( name: "oracle/weblogic/http/" + port + "/found_service_urls", value: http_report_vuln_url( port: port, url: endpoint, url_only: TRUE ) );
	}
}
set_kb_item( name: "oracle/weblogic/detected", value: TRUE );
set_kb_item( name: "oracle/weblogic/http/detected", value: TRUE );
set_kb_item( name: "oracle/weblogic/http/port", value: port );
set_kb_item( name: "oracle/weblogic/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
set_kb_item( name: "oracle/weblogic/http/" + port + "/version", value: version );
set_kb_item( name: "oracle/weblogic/http/" + port + "/servicepack", value: servicepack );
exit( 0 );

