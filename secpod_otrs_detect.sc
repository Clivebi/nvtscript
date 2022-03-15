if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902018" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)" );
	script_name( "Open Ticket Request System (OTRS) and ITSM Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of
  Open Ticket Request System (OTRS) and ITSM.

  The script sends a connection request to the server and attempts to extract
  the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
features = make_array( "/public.pl?Action=PublicFAQExplorer#---#FAQ", "(<title>FAQ - .*</title>|<h1>FAQ Explorer</h1>)", "/public.pl?Action=PublicSurvey#---#Survey", "(<title>Survey - .*</title>|<h2> Survey Error! </h2>)", "/public.pl?Action=PublicCalendar#---#OTRSAppointmentCalendar", "<p>No CalendarID!</p>", "/index.pl#---#Fred", "<div class=\"(DevelFredBox|DevelFredContainer)\"", "/public.pl?Action=PublicRepository#---#Public package repository", "<title>PublicRepository.*</title>" );
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/support", "/OTRS", "/otrs", http_cgi_dirs( port: port ) ) {
	otrsInstalled = FALSE;
	conclUrl = NULL;
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for path in make_list( "/public.pl",
		 "/installer.pl",
		 "/index.pl" ) {
		url = dir + path;
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(res && egrep( pattern: "(Powered by OTRS|Powered by.*OTRS|<title>Login - OTRS</title>)", string: res )){
			otrsInstalled = TRUE;
			vers = "unknown";
			otrsVer = eregmatch( pattern: "title=\"OTRS ([0-9.]+)\"", string: res );
			if(otrsVer[1]){
				vers = otrsVer[1];
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
			if(vers == "unknown"){
				otrsVer = eregmatch( pattern: "Powered by.*>OTRS ([0-9.]+)<", string: res );
				if(otrsVer[1]){
					vers = otrsVer[1];
					conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				}
			}
			if(vers == "unknown"){
				otrsVer = eregmatch( pattern: ">Powered by OTRS ([0-9.]+)<", string: res );
				if(otrsVer[1]){
					vers = otrsVer[1];
					conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				}
			}
			if(vers != "unknown"){
				break;
			}
		}
	}
	if(otrsInstalled){
		extra = "";
		for feature in keys( features ) {
			_split = split( buffer: feature, sep: "#---#", keep: FALSE );
			if(max_index( _split ) != 2){
				continue;
			}
			_feature = _split[0];
			_desc = _split[1];
			url = dir + _feature;
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			if(egrep( string: res, pattern: features[feature] )){
				extra += http_report_vuln_url( url: url, port: port, url_only: TRUE ) + " (Feature: " + _desc + ")\n";
			}
		}
		if(extra){
			extra = "The following additional installed features have been identified:\n\n" + extra;
		}
		if(vers != "unknown"){
			set_kb_item( name: "www/" + port + "/OTRS", value: vers + " under " + install );
		}
		set_kb_item( name: "OTRS/installed", value: TRUE );
		register_and_report_cpe( app: "OTRS", ver: vers, concluded: otrsVer[0], conclUrl: conclUrl, base: "cpe:/a:otrs:otrs:", expr: "^([0-9.]+)", insloc: install, regPort: port, regService: "www", extra: extra );
	}
	url = dir + "/index.pl";
	res = http_get_cache( item: url, port: port );
	if(res && ( ContainsString( res, "Welcome to OTRS::ITSM" ) || ContainsString( res, "<title>Login - OTRS::ITSM" ) )){
		vers = "unknown";
		itsmver = eregmatch( pattern: "Welcome to OTRS::ITSM ([0-9\\.\\w]+)", string: res );
		if(itsmver[1]){
			vers = itsmver[1];
			set_kb_item( name: "www/" + port + "/OTRS ITSM", value: vers + " under " + install );
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		set_kb_item( name: "OTRS ITSM/installed", value: TRUE );
		register_and_report_cpe( app: "OTRS ITSM", ver: vers, concluded: itsmver[0], conclUrl: conclUrl, base: "cpe:/a:otrs:otrs_itsm:", expr: "^([0-9.]+)", insloc: install, regPort: port, regService: "www" );
	}
}
exit( 0 );

