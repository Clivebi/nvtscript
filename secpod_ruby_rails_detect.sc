if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902089" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)" );
	script_name( "Ruby on Rails Detection (HTTP)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 3000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Ruby on Rails

  In addition this script also tries to detect Ruby itself." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 3000 );
rootInstalled = FALSE;
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(rootInstalled){
		break;
	}
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: dir + "/rails/info/properties/", port: port );
	rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
	sndReq2 = http_get( item: dir + "/doesnt_exist/", port: port );
	rcvRes2 = http_keepalive_send_recv( port: port, data: sndReq2 );
	sndReq3 = http_get( item: dir + "/rails/info/routes/", port: port );
	rcvRes3 = http_keepalive_send_recv( port: port, data: sndReq3 );
	if(ContainsString( rcvRes, ">Ruby version<" ) || ContainsString( rcvRes, ">Rails version<" ) || ContainsString( rcvRes, "<title>Routes</title>" ) || ContainsString( rcvRes2, "<title>Action Controller: Exception caught</title>" ) || ContainsString( rcvRes3, "<title>Routes</title>" )){
		rorVersion = "unknown";
		railsVersion = "unknown";
		concl = http_report_vuln_url( port: port, url: dir + "/doesnt_exist/", url_only: TRUE ) + " or " + http_report_vuln_url( port: port, url: dir + "/rails/info/routes/", url_only: TRUE );
		if(dir == ""){
			rootInstalled = TRUE;
		}
		rorVer = eregmatch( pattern: ">Rails version.[^\"]*\"value\">([0-9.]+)(.?(p|patchlevel) ?([0-9]+))?", string: rcvRes );
		if(!isnull( rorVer[0] )){
			concl = http_report_vuln_url( port: port, url: dir + "/rails/info/properties/", url_only: TRUE );
			if(!isnull( rorVer[1] )){
				if( !isnull( rorVer[2] ) ){
					rorVersion = rorVer[1] + "." + rorVer[4];
				}
				else {
					rorVersion = rorVer[1];
				}
			}
		}
		if(rorVersion != "unknown"){
			set_kb_item( name: "rails/detected", value: TRUE );
			set_kb_item( name: "rails/http/detected", value: TRUE );
			set_kb_item( name: "rails/http/port", value: port );
			set_kb_item( name: "rails/http/" + port + "/install", value: port + "#---#" + install + "#---#" + rorVersion + "#---#" + rorVer[0] + "#---#" + concl );
		}
		rubyVersion = "unknown";
		rubyVer = eregmatch( pattern: ">Ruby version.[^\"]*\"value\">([0-9.]+)(.?(p|patchlevel) ?([0-9]+))?", string: rcvRes );
		if(!isnull( rubyVer[0] )){
			concl = http_report_vuln_url( port: port, url: dir + "/rails/info/properties/", url_only: TRUE );
			if(!isnull( rubyVer[1] )){
				if( !isnull( rubyVer[2] ) ){
					rubyVersion = rubyVer[1] + "." + rubyVer[4];
				}
				else {
					rubyVersion = rubyVer[1];
				}
			}
		}
		if(rubyVersion != "unknown"){
			set_kb_item( name: "ruby/detected", value: TRUE );
			set_kb_item( name: "ruby/http/detected", value: TRUE );
			set_kb_item( name: "ruby/http/port", value: port );
			set_kb_item( name: "ruby/http/" + port + "/install", value: port + "#---#" + install + "#---#" + rubyVersion + "#---#" + rubyVer[0] + "#---#" + concl );
		}
	}
}
exit( 0 );

