if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114088" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-03-28 12:23:30 +0100 (Thu, 28 Mar 2019)" );
	script_name( "Carel pCOWeb Devices Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 10000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installation of
  Carel's pCOWeb management software for various devices.

  This script sends an HTTP GET request to try to ensure the presence of
  the pCOWeb web interface." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 10000 );
url1 = "/";
url2 = "/http/index.html";
res1 = http_get_cache( port: port, item: url1 );
if(ContainsString( res1, "Carel pCOWeb Home Page" ) && ContainsString( res1, "<h2>This page will be redirected <a href" ) && ContainsString( res1, "location=" )){
	version = "unknown";
	appName = "Carel pCOWeb Device";
	cpe = "cpe:/h:carel:pcoweb_card:";
	set_kb_item( name: "carel/pcoweb/device/detected", value: TRUE );
	res2 = http_get_cache( port: port, item: url2 );
	if( ContainsString( res2, "Rehau" ) && ContainsString( res2, "URL=default.html" ) ){
		appName = "Carel pCOWeb Rehau Group Temperature Control System";
		set_kb_item( name: "carel/pcoweb/rehau/temperature_controller/detected", value: TRUE );
		verUrl = "/http/hc/SysInfo.html";
		req3 = http_get_req( port: port, url: verUrl );
		res3 = http_send_recv( port: port, data: req3 );
		biosMajor = eregmatch( pattern: "\"versionBios\"\\s*[^>]+>[^;]+;([0-9]+).", string: res3, icase: TRUE );
		biosMinor = eregmatch( pattern: "var\\s*biosMinor\\s*=parseInt\\(([0-9]+)\\);", string: res3, icase: TRUE );
		if(!isnull( biosMajor[1] )){
			if( isnull( biosMinor[1] ) ){
				version = biosMajor[1];
				conclVer = biosMajor[0];
			}
			else {
				version = biosMajor[1] + "." + biosMinor[1];
				conclVer = biosMajor[0] + "\n" + biosMinor[0];
			}
		}
		cpe = "cpe:/h:carel:pcoweb_rehau_temperature_controller:";
	}
	else {
		if( ContainsString( res2, "RDZ pCOWeb Application" ) && ContainsString( res2, "location=\"/http/rdz/index.html\";" ) ){
			appName = "Carel pCOWeb RDZ Controller";
			set_kb_item( name: "carel/pcoweb/rdz/controller/detected", value: TRUE );
			verUrl = "/http/rdz/application.html";
			req3 = http_get_req( port: port, url: verUrl );
			res3 = http_send_recv( port: port, data: req3 );
			ver = eregmatch( pattern: "Ver.\\s*([0-9.]+)</div>", string: res3, icase: TRUE );
			if(!isnull( ver[1] )){
				version = ver[1];
				conclVer = ver[0];
			}
			cpe = "cpe:/h:carel:pcoweb_rdz_controller:";
		}
		else {
			if( ContainsString( res2, "pCOWeb Default Page" ) || ContainsString( res2, "This is the default index.html provided by Carel Industries S.r.l." ) ){
				appName = "Carel pCOWeb Default Page";
				set_kb_item( name: "carel/pcoweb/default_page/detected", value: TRUE );
				cpe = "cpe:/a:carel:pcoweb_default_page:";
			}
			else {
				if( ContainsString( res2, "function getVariables() {" ) && ContainsString( res2, "getParams('/usr-cgi/xml.cgi'" ) ){
					appName = "Carel pCOWeb GSI Heat Pump";
					set_kb_item( name: "carel/pcoweb/gsi/heat_pump/detected", value: TRUE );
					cpe = "cpe:/h:carel:pcoweb_gsi_heat_pump:";
				}
				else {
					if( ContainsString( res2, "function WriteALR()" ) && ContainsString( res2, "function WebDate()" ) && ContainsString( res2, "function WebHour()" ) ){
						appName = "Carel pCOWeb Nalon Heat Pump";
						set_kb_item( name: "carel/pcoweb/nalon/heat_pump/detected", value: TRUE );
						cpe = "cpe:/h:carel:pcoweb_nalon_heat_pump:";
					}
					else {
						glenUrl = "/http/index/j_operatingdata.html";
						req3 = http_get_req( port: port, url: glenUrl );
						res3 = http_send_recv( port: port, data: req3 );
						if(ContainsString( res2, "function vorlader()" ) && ContainsString( res2, "<body onLoad=\"vorlader()\">" ) || ContainsString( res3, "<script>var bios" ) && ContainsString( res3, "<script>var boot" )){
							appName = "Carel pCOWeb Glen Dimplex Brine To Water Heat Pump";
							set_kb_item( name: "carel/pcoweb/glen_dimplex/heat_pump/detected", value: TRUE );
							biosVer = eregmatch( pattern: "<script>var bios\\s*=\\s*([0-9]*)([0-9]).([0-9]+);", string: res3, icase: TRUE );
							if(( !isnull( biosVer[2] ) && !isnull( biosVer[3] ) ) || ( !isnull( biosVer[1] ) && !isnull( biosVer[2] ) && !isnull( biosVer[3] ) )){
								version = biosVer[1] + "." + biosVer[2] + biosVer[3];
								conclVer = biosVer[0];
							}
							cpe = "cpe:/h:carel:pcoweb_glen_dimplex_heat_pump:";
						}
					}
				}
			}
		}
	}
	conclUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
	register_and_report_cpe( app: appName, ver: version, concluded: conclVer, base: cpe, expr: "^([0-9.]+)", insloc: "/", regPort: port, regService: "www", conclUrl: conclUrl );
}
exit( 0 );

