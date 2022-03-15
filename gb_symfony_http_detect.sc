if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107323" );
	script_version( "2021-06-17T10:24:47+0000" );
	script_tag( name: "last_modification", value: "2021-06-17 10:24:47 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-26 16:20:53 +0200 (Tue, 26 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Sensiolabs Symfony Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8000, 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Sensiolabs Symfony." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 8000 );
buf = http_get_cache( item: "/", port: port, fetch404: TRUE );
if(IsMatchRegexp( buf, "<h1><(span|small)>Welcome to</(span|small)> Symfony( | <span class=\"version\">)[0-9.]+(</span>)?</h1>" )){
	install = "/";
	version = "unknown";
	found = TRUE;
	vers1 = eregmatch( pattern: "Symfony( | <span class=\"version\">)([0-9.]+)(</span>)?</h1>", string: buf );
	if(vers1[2]){
		version = vers1[2];
	}
	conclUrl = http_report_vuln_url( port: port, url: "/", url_only: TRUE );
	set_kb_item( name: "symfony/http/" + port + "/installs", value: port + "#---#" + install + "#---#" + version + "#---#" + vers1[0] + "#---#" + conclUrl );
}
if(!found){
	buf = http_get_cache( item: "/_profiler/latest", port: port );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "<title>Symfony Profiler</title>" ) || IsMatchRegexp( buf, "https?://(www\\.)?symfony\\.com/search" ) )){
		install = "/";
		version = "unknown";
		found = TRUE;
		url = "/_profiler/latest?ip=&limit=1";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		match = eregmatch( string: buf, pattern: "<dt>Token</dt>.*<dd>([0-9a-z]+)</dd>", icase: TRUE );
		if(match[1]){
			url = "/_profiler/" + match[1] + "?panel=config";
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			if(ContainsString( buf, "<h2>Symfony Configuration</h2>" )){
				vers2 = eregmatch( pattern: "value\">([0-9.]+)</span>", string: buf );
				if(vers2[1]){
					version = vers2[1];
				}
			}
		}
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		set_kb_item( name: "symfony/http/" + port + "/installs", value: port + "#---#" + install + "#---#" + version + "#---#" + vers2[0] + "#---#" + conclUrl );
	}
}
for dir in nasl_make_list_unique( "/", "/symfony", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/web/app_dev.php/_configurator/step/0";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "Symfony Standard Edition" )){
		version = "unknown";
		found = TRUE;
		vers3 = eregmatch( string: buf, pattern: "Symfony Standard Edition v\\.([0-9.]+)", icase: TRUE );
		if(vers3[1]){
			version = vers3[1];
		}
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		set_kb_item( name: "symfony/http/" + port + "/installs", value: port + "#---#" + install + "#---#" + version + "#---#" + vers3[0] + "#---#" + conclUrl );
	}
	url = dir + "/app.php";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "Framework Symfony Version" )){
		version = "unknown";
		found = TRUE;
		vers4 = eregmatch( string: buf, pattern: "Framework Symfony Version ([0-9.]+)", icase: TRUE );
		if(vers4[1]){
			version = vers4[1];
		}
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		set_kb_item( name: "symfony/http/" + port + "/installs", value: port + "#---#" + install + "#---#" + version + "#---#" + vers4[0] + "#---#" + conclUrl );
	}
	url = dir + "/login";
	buf = http_get_cache( item: url, port: port );
	vers5 = eregmatch( string: buf, pattern: "box-symfony-version\">.*Symfony ([0-9.]+)", icase: TRUE );
	if(vers5[1]){
		version = vers5[1];
		found = TRUE;
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		set_kb_item( name: "symfony/http/" + port + "/installs", value: port + "#---#" + install + "#---#" + version + "#---#" + vers5[0] + "#---#" + conclUrl );
	}
	url = dir + "/src/Symfony/Component/Console/CHANGELOG.md";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(IsMatchRegexp( buf, "^CHANGELOG" ) && egrep( string: buf, pattern: "^=========" ) && vers6 = egrep( string: buf, pattern: "^([0-9.]+)" )){
		vers6 = eregmatch( string: vers6, pattern: "^([0-9.]+)" );
		version = vers6[1];
		found = TRUE;
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		set_kb_item( name: "symfony/http/" + port + "/installs", value: port + "#---#" + install + "#---#" + version + "#---#" + vers6[0] + "#---#" + conclUrl );
	}
}
if(found){
	set_kb_item( name: "symfony/detected", value: TRUE );
	set_kb_item( name: "symfony/http/detected", value: TRUE );
	set_kb_item( name: "symfony/http/port", value: port );
}
exit( 0 );

