if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117074" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-12-11 12:52:04 +0000 (Fri, 11 Dec 2020)" );
	script_name( "D-Link DSR Devices Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of D-Link DSL Devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 443 );
url = "/";
buf = http_get_cache( port: port, item: url );
if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
	exit( 0 );
}
if(ContainsString( buf, "URL=/scgi-bin/platform.cgi\"" )){
	url = "/scgi-bin/platform.cgi";
	buf = http_get_cache( port: port, item: url );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
		exit( 0 );
	}
}
if(IsMatchRegexp( buf, "<title>D-Link\\s*:\\s*Unified Services Router\\s*</title>" ) && ContainsString( buf, "DSR-" )){
	set_kb_item( name: "Host/is_d-link_dsr_device", value: TRUE );
	set_kb_item( name: "Host/is_dlink_device", value: TRUE );
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	fw_version = "unknown";
	os_app = "D-Link DSR";
	os_cpe = "cpe:/o:d-link:dsr";
	hw_version = "unknown";
	hw_app = "D-Link DSR";
	hw_cpe = "cpe:/h:d-link:dsr";
	model = "unknown";
	install = "/";
	mo = eregmatch( pattern: "(>Product Page\\s*:\\s*|>Produktseite\\s*:\\s*|Unified Services Router\\s*-\\s*|>)DSR-([^< ]+)", string: buf );
	if( mo[2] ){
		model = mo[2];
		os_concl = mo[0];
		hw_concl = mo[0];
		os_app += "-" + model + " Firmware";
		os_cpe += "-" + tolower( model ) + "_firmware";
		hw_app += "-" + model + " Device";
		hw_cpe += "-" + tolower( model );
		set_kb_item( name: "d-link/dsr/model", value: model );
	}
	else {
		os_app += " Unknown Model Firmware";
		os_cpe += "-unknown_model_firmware";
		hw_app += " Unknown Model Device";
		hw_cpe += "-unknown_model";
	}
	fw_ver = eregmatch( pattern: ">Firmware[ -]Version\\s*:\\s*([^<]+)<", string: buf );
	if(fw_ver[1]){
		fw_version = fw_ver[1];
	}
	hw_ver = eregmatch( pattern: ">Hardware[ -]Version\\s*:\\s*([^<]+)<", string: buf );
	if(hw_ver[1]){
		hw_version = hw_ver[1];
	}
	if(fw_version == "unknown" || hw_version == "unknown"){
		hw_fw_class = egrep( string: buf, pattern: "<div class=\"floatR txt01\">[^<]+<", icase: FALSE );
		if(hw_fw_class){
			list = split( buffer: hw_fw_class, keep: FALSE );
			for item in list {
				if(fw_version == "unknown"){
					fw_ver = eregmatch( pattern: ">[^:]+:\\s*([0-9.]{3,}[^<]*)<", string: item, icase: FALSE );
					if(fw_ver[1]){
						fw_version = fw_ver[1];
						continue;
					}
				}
				if(hw_version == "unknown"){
					hw_ver = eregmatch( pattern: ">[^:]+:\\s*([A-Z][0-9]*)<", string: item, icase: FALSE );
					if(hw_ver[1]){
						hw_version = hw_ver[1];
						continue;
					}
				}
			}
		}
	}
	if(fw_version != "unknown"){
		os_cpe += ":" + tolower( fw_version );
		set_kb_item( name: "d-link/dsr/fw_version", value: fw_version );
		if(os_concl){
			os_concl += "\n";
		}
		os_concl += fw_ver[0];
	}
	if(hw_version != "unknown"){
		hw_cpe += ":" + tolower( hw_version );
		set_kb_item( name: "d-link/dsr/hw_version", value: hw_version );
		if(hw_concl){
			hw_concl += "\n";
		}
		hw_concl += hw_ver[0];
	}
	os_register_and_report( os: os_app, cpe: os_cpe, banner_type: "D-Link DSR Device Login Page", port: port, desc: "D-Link DSR Devices Detection (HTTP)", runs_key: "unixoide" );
	register_product( cpe: os_cpe, location: install, port: port, service: "www" );
	register_product( cpe: hw_cpe, location: install, port: port, service: "www" );
	report = build_detection_report( app: os_app, version: fw_version, concluded: os_concl, concludedUrl: conclUrl, install: install, cpe: os_cpe );
	report += "\n\n" + build_detection_report( app: hw_app, version: hw_version, concluded: hw_concl, install: install, cpe: hw_cpe );
	log_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

