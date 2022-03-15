if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111001" );
	script_version( "2021-05-26T11:52:35+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 11:52:35 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2015-03-02 12:00:00 +0100 (Mon, 02 Mar 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Jenkins Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of the Jenkins automation server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8080 );
for dir in nasl_make_list_unique( "/", "/jenkins", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	buf1 = http_get_cache( item: dir + "/", port: port );
	headers1 = http_extract_headers_from_response( data: buf1 );
	buf2 = http_get_cache( item: dir + "/login", port: port );
	if(ContainsString( buf1, "Welcome to Jenkins!" ) || ContainsString( buf1, "<title>Dashboard [Jenkins]</title>" ) || IsMatchRegexp( headers1, "X-Jenkins\\s*:" ) || ContainsString( buf2, "<title>Jenkins</title>" ) || ContainsString( buf2, "<title>Sign in [Jenkins]</title>" )){
		version = "unknown";
		ver = eregmatch( pattern: "Jenkins ver\\. ([0-9.]+)", string: buf1 );
		if(!isnull( ver[1] )){
			version = ver[1];
		}
		if(version == "unknown"){
			ver = eregmatch( pattern: "X-Jenkins\\s*:\\s*([0-9.]+)", string: headers1, icase: TRUE );
			if(!isnull( ver[1] )){
				version = ver[1];
			}
		}
		if(version == "unknown"){
			ver = eregmatch( pattern: "Jenkins ver\\. ([0-9.]+)", string: buf2 );
			if(!isnull( ver[1] )){
				version = ver[1];
			}
		}
		if(version && version != "unknown"){
			if(IsMatchRegexp( version, "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
				set_kb_item( name: "jenkins/" + port + "/is_lts", value: TRUE );
			}
		}
		set_kb_item( name: "jenkins/detected", value: TRUE );
		set_kb_item( name: "jenkins/http/detected", value: TRUE );
		set_kb_item( name: "jenkins/http/port", value: port );
		set_kb_item( name: "jenkins/http/" + port + "/location", value: install );
		if(version != "unknown"){
			set_kb_item( name: "jenkins/http/" + port + "/version", value: version );
			set_kb_item( name: "jenkins/http/" + port + "/concluded", value: ver[0] );
		}
		cli_port = eregmatch( pattern: "X-Jenkins-CLI-Port\\s*:\\s*([^\r\n]+)", string: headers1, icase: TRUE );
		if(!isnull( cli_port[1] )){
			set_kb_item( name: "jenkins/cli_port", value: cli_port[1] );
			if(get_port_state( cli_port )){
				service_register( port: cli_port[1], proto: "jenkins_cli" );
			}
		}
		cli_port2 = eregmatch( pattern: "X-Jenkins-CLI2-Port\\s*:\\s*([^\r\n]+)", string: headers1, icase: TRUE );
		if(!isnull( cli_port2[1] ) && cli_port2[1] != cli_port[1]){
			set_kb_item( name: "jenkins/cli_port", value: cli_port2[1] );
			if(get_port_state( cli_port2 )){
				service_register( port: cli_port2[1], proto: "jenkins_cli" );
			}
		}
		req = http_get( item: dir + "/asynchPeople/api/xml", port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(IsMatchRegexp( buf, "^<people _class=" ) || ContainsString( buf, "<absoluteUrl>" ) || ContainsString( buf, "<fullName>" )){
			set_kb_item( name: "jenkins/" + port + "/anonymous_read_enabled", value: TRUE );
			set_kb_item( name: "jenkins/" + port + "/" + install + "/anonymous_read_enabled", value: TRUE );
			set_kb_item( name: "jenkins/anonymous_read_enabled", value: TRUE );
			users = split( buffer: buf, sep: "</user>", keep: FALSE );
			for user in users {
				_user = eregmatch( pattern: "<absoluteUrl>[^>]+/user/([^>]+)</absoluteUrl>", string: user, icase: FALSE );
				if(_user[1]){
					set_kb_item( name: "jenkins/" + port + "/user_list", value: _user[1] );
				}
			}
		}
		url = dir + "/whoAmI/";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "<title>Who Am I [Jenkins]</title>" ) || ContainsString( buf, "<td>IsAuthenticated" ) )){
			set_kb_item( name: "jenkins/" + port + "/whoami_available", value: TRUE );
			set_kb_item( name: "jenkins/" + port + "/" + install + "/whoami_available", value: TRUE );
			set_kb_item( name: "jenkins/" + port + "/" + install + "/whoami_url", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
			set_kb_item( name: "jenkins/whoami_available", value: TRUE );
		}
		exit( 0 );
	}
}
exit( 0 );

