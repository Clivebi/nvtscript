if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810234" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-12-09 15:22:03 +0530 (Fri, 09 Dec 2016)" );
	script_name( "D-Link DAP Devices Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of D-Link DAP Devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_cache( item: "/", port: port );
buf2 = http_get_cache( item: "/index.php", port: port );
buf3 = http_get_cache( item: "/cgi-bin/webproc", port: port );
if(( IsMatchRegexp( buf, "Product Page ?:.*>DAP" ) || IsMatchRegexp( buf, "class=\"pp\">.*>DAP" ) || IsMatchRegexp( buf, "fw_ver\"> DAP-[0-9]+" ) || IsMatchRegexp( buf2, "<big>DAP-[0-9]+" ) || ContainsString( buf3, "target=_blank>DAP-" ) ) && ( IsMatchRegexp( buf, ">Copyright.*D-Link" ) || IsMatchRegexp( buf, "<title>D-LINK" ) || IsMatchRegexp( buf2, "<title>D-Link" ) || IsMatchRegexp( buf3, "\"copy(w)?right.*D-Link" ) )){
	set_kb_item( name: "Host/is_dlink_dap_device", value: TRUE );
	set_kb_item( name: "Host/is_dlink_device", value: TRUE );
	fw_version = "unknown";
	os_app = "D-Link DAP";
	os_cpe = "cpe:/o:d-link:dap";
	hw_version = "unknown";
	hw_app = "D-Link DAP";
	hw_cpe = "cpe:/h:d-link:dap";
	model = "unknown";
	install = "/";
	if(IsMatchRegexp( buf2, "<big>DAP-[0-9]+" )){
		buf = buf2;
	}
	mo = eregmatch( pattern: "> ?DAP-([0-9.]+)", string: buf );
	if(isnull( mo[1] )){
		mo = eregmatch( pattern: "target=_blank>DAP-([0-9]+)", string: buf3 );
	}
	if( mo[1] ){
		model = mo[1];
		os_app += "-" + model + " Firmware";
		os_cpe += "-" + model + "_firmware";
		hw_app += "-" + model + " Device";
		hw_cpe += "-" + model;
		set_kb_item( name: "d-link/dap/model", value: model );
		fw_concluded = mo[0];
		hw_concluded = mo[0];
	}
	else {
		os_app += " Unknown Model Firmware";
		os_cpe += "-unknown_model_firmware";
		hw_app += " Unknown Model Device";
		hw_cpe += "-unknown_model";
	}
	fw_ver = eregmatch( pattern: "Firmware Version ?: V?([0-9.]+)", string: buf );
	if(fw_ver[1]){
		fw_version = fw_ver[1];
	}
	if(!fw_ver[1]){
		fw_ver = eregmatch( pattern: "id=\"fw_ver\" align=\"left\">([0-9.]+)", string: buf );
		if( fw_ver[1] ){
			fw_version = fw_ver[1];
		}
		else {
			fw_ver = eregmatch( pattern: "id=\"fw_ver\">([0-9.]+)", string: buf );
			if( fw_ver[1] ){
				fw_version = fw_ver[1];
			}
			else {
				fw_ver = eregmatch( pattern: "Firmware Version[^0-9]+([0-9.]+)", string: buf );
				if( fw_ver[1] ){
					fw_version = fw_ver[1];
				}
				else {
					fw_ver = eregmatch( pattern: "\"DIV_SoftwareVersion\"[^>]+>[^>]+>[^>]+>([0-9.]+)<", string: buf3 );
					if(fw_ver[1]){
						fw_version = fw_ver[1];
					}
				}
			}
		}
	}
	if(fw_version != "unknown"){
		os_cpe += ":" + fw_version;
		set_kb_item( name: "d-link/dap/fw_version", value: fw_version );
		if(fw_concluded){
			fw_concluded += "\n";
		}
		fw_concluded += fw_ver[0];
	}
	hw_ver = eregmatch( pattern: ">Hardware Version ?: ([0-9A-Za-z.]+)", string: buf );
	if(hw_ver[1]){
		hw_version = hw_ver[1];
	}
	if(!hw_ver[1]){
		hw_ver = eregmatch( pattern: "id=\"hw_ver\" align=\"left\">([0-9A-Za-z.]+)", string: buf );
		if( hw_ver[1] ){
			hw_version = hw_ver[1];
		}
		else {
			hw_ver = eregmatch( pattern: ">show_words\\(TA3\\)[^=]+=\"fw_ver\"> ([0-9A-Z]+)", string: buf );
			if( hw_ver[1] ){
				hw_version = hw_ver[1];
			}
			else {
				hw_ver = eregmatch( pattern: ">Hardware Version[^ ]+ ([0-9A-Z]+)", string: buf );
				if( hw_ver[1] ){
					hw_version = hw_ver[1];
				}
				else {
					hw_ver = eregmatch( pattern: "\"DIV_HardwareVersion\"[^>]+>[^>]+>[^>]+>([0-9A-Z]+)<", string: buf3 );
					if(hw_ver[1]){
						hw_version = hw_ver[1];
					}
				}
			}
		}
	}
	if(hw_version != "unknown"){
		hw_cpe += ":" + tolower( hw_version );
		set_kb_item( name: "d-link/dap/hw_version", value: hw_version );
		if(hw_concluded){
			hw_concluded += "\n";
		}
		hw_concluded += hw_ver[0];
	}
	os_register_and_report( os: os_app, cpe: os_cpe, banner_type: "D-Link DAP Device Login Page", port: port, desc: "D-Link DAP Devices Detection", runs_key: "unixoide" );
	register_product( cpe: os_cpe, location: install, port: port, service: "www" );
	register_product( cpe: hw_cpe, location: install, port: port, service: "www" );
	report = build_detection_report( app: os_app, version: fw_version, concluded: fw_concluded, install: install, cpe: os_cpe );
	report += "\n\n" + build_detection_report( app: hw_app, version: hw_version, concluded: hw_concluded, install: install, cpe: hw_cpe );
	log_message( port: port, data: report );
}
exit( 0 );

