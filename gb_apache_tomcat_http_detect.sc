if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800371" );
	script_version( "2021-03-11T13:37:30+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-11 13:37:30 +0000 (Thu, 11 Mar 2021)" );
	script_tag( name: "creation_date", value: "2009-03-18 14:25:01 +0100 (Wed, 18 Mar 2009)" );
	script_name( "Apache Tomcat Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Apache Tomcat." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
verPattern = "<strong>Tomcat ([0-9.]+)(-(RC|M)([0-9.]+))?";
verPattern2 = "Apache Tomcat( Version |\\/)([0-9.]+)(-(RC|M)([0-9.]+))?";
conclPattern = "(Apache Tomcat|Tomcat (Host )?Manager Application)[^\r\n]+";
port = http_get_port( default: 8080 );
host = http_host_name( dont_add_port: TRUE );
identified = FALSE;
verFound = FALSE;
conclUrl = "";
_conclUrl = "";
for file in make_list( "/tomcat-docs/changelog.html",
	 "/docs/changelog.html",
	 "/RELEASE-NOTES.txt",
	 "/docs/RELEASE-NOTES.txt",
	 "/index.jsp" ) {
	res = http_get_cache( item: file, port: port );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Apache Tomcat" )){
		_concluded = eregmatch( string: res, pattern: conclPattern, icase: FALSE );
		if(_concluded){
			concluded = _concluded[0];
		}
		identified = TRUE;
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 404" )){
		continue;
	}
	if(egrep( pattern: verPattern, string: res ) || egrep( pattern: verPattern2, string: res )){
		if(conclUrl){
			conclUrl += "\n";
		}
		conclUrl += http_report_vuln_url( port: port, url: file, url_only: TRUE );
		verFound = TRUE;
		break;
	}
}
if(!verFound){
	for file in make_list( "/",
		 "/vt-test-non-existent.html",
		 "/vt-test/vt-test-non-existent.html" ) {
		res = http_get_cache( item: file, port: port, fetch404: TRUE );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 404" ) && ContainsString( res, "Apache Tomcat" )){
			_concluded = eregmatch( string: res, pattern: conclPattern, icase: FALSE );
			if(_concluded){
				concluded = _concluded[0];
			}
			identified = TRUE;
			if(_conclUrl){
				_conclUrl += "\n";
			}
			_conclUrl = http_report_vuln_url( port: port, url: file, url_only: TRUE );
		}
		if(egrep( pattern: verPattern2, string: res )){
			if(conclUrl){
				conclUrl += "\n";
			}
			conclUrl += http_report_vuln_url( port: port, url: file, url_only: TRUE );
			verFound = TRUE;
			break;
		}
	}
	if(identified && !conclUrl){
		conclUrl += _conclUrl;
	}
}
authDirs = http_get_kb_auth_required( port: port, host: host );
if(authDirs){
	authDirs = sort( authDirs );
	for url in authDirs {
		if(!ContainsString( url, "manager/" )){
			continue;
		}
		authReq = http_get( item: url, port: port );
		authRes = http_keepalive_send_recv( port: port, data: authReq, bodyonly: FALSE );
		if(IsMatchRegexp( authRes, "^HTTP/1\\.[01] 401" )){
			if(ContainsString( authRes, "Tomcat Manager Application" ) || ContainsString( authRes, "Tomcat Host Manager Application" ) || ContainsString( authRes, "Tomcat Manager Application" )){
				_concluded = eregmatch( string: authRes, pattern: conclPattern, icase: FALSE );
				if(_concluded){
					concluded = _concluded[0];
				}
				set_kb_item( name: "www/" + host + "/" + port + "/ApacheTomcat/auth_required", value: url );
				set_kb_item( name: "ApacheTomcat/auth_required", value: TRUE );
				identified = TRUE;
				if(conclUrl){
					conclUrl += "\n";
				}
				conclUrl += http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
	}
}
if(identified){
	vers = "unknown";
	install = port + "/tcp";
	version = eregmatch( pattern: verPattern, string: res );
	if( ContainsString( version[0], "<strong>Tomcat" ) && !isnull( version[1] ) ){
		vers = version[1];
		if(version[2]){
			version[2] = ereg_replace( pattern: "-", string: version[2], replace: "." );
			vers = version[1] + version[2];
			concluded = version[0];
		}
	}
	else {
		version = eregmatch( pattern: verPattern2, string: res );
		if(ContainsString( version[0], "Apache Tomcat" ) && !isnull( version[2] )){
			concluded = version[0];
			vers = version[2];
			if(version[3]){
				version[3] = ereg_replace( pattern: "-", string: version[3], replace: "." );
				vers = version[2] + version[3];
			}
		}
	}
	set_kb_item( name: "apache/tomcat/detected", value: TRUE );
	set_kb_item( name: "apache/tomcat/http/detected", value: TRUE );
	set_kb_item( name: "apache/tomcat/http/" + port + "/installs", value: port + "#---#" + install + "#---#" + vers + "#---#" + concluded + "#---#" + conclUrl );
}
exit( 0 );

