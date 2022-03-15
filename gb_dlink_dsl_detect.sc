if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812377" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-01-03 16:00:40 +0530 (Wed, 03 Jan 2018)" );
	script_name( "D-Link DSL Devices Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "D-LinkDSL/banner" );
	script_tag( name: "summary", value: "HTTP based detection of D-Link DSL Devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
for url in make_list( "/",
	 "/cgi-bin/webproc" ) {
	buf = http_get_cache( port: port, item: url );
	if(!egrep( string: buf, pattern: "^Server\\s*:\\s*(Boa|micro_httpd|Linux|RomPager|uhttpd)", icase: TRUE ) && !ContainsString( buf, "/cgi-bin/SETUP/sp_home.asp" ) && !ContainsString( buf, "/page/login/login.html" )){
		continue;
	}
	if(IsMatchRegexp( buf, "Location: /page/login/login.html" )){
		buf = http_get_cache( port: port, item: "/page/login/login.html" );
	}
	if(ContainsString( buf, "WWW-Authenticate: Basic realm=\"DSL-([0-9A-Z]+)" ) || ContainsString( buf, "<title>D-Link DSL-" ) || ( ContainsString( buf, "D-Link" ) && ( ContainsString( buf, "Product Page : DSL-" ) || ContainsString( buf, "Server: Linux, WEBACCESS/1.0, DSL-" ) ) ) || ( ContainsString( buf, "DSL Router" ) && IsMatchRegexp( buf, "Copyright.*D-Link Systems" ) ) || ( ContainsString( buf, "<TITLE>DSL-" ) && ContainsString( buf, "var PingDlink" ) ) || ( ContainsString( buf, "var Manufacturer=\"D-Link\"" ) && ContainsString( buf, "var ModelName=\"DSL-" ) )){
		set_kb_item( name: "Host/is_dlink_dsl_device", value: TRUE );
		set_kb_item( name: "Host/is_dlink_device", value: TRUE );
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		fw_version = "unknown";
		os_app = "D-Link DSL";
		os_cpe = "cpe:/o:d-link:dsl";
		hw_version = "unknown";
		hw_app = "D-Link DSL";
		hw_cpe = "cpe:/h:d-link:dsl";
		model = "unknown";
		install = "/";
		mo = eregmatch( pattern: "(Product Page ?: ?|var ModelName=\"|Server: Linux, WEBACCESS/1\\.0, )?DSL-([0-9A-Z]+)", string: buf );
		if( mo[2] ){
			model = mo[2];
			os_concl = mo[0];
			hw_concl = mo[0];
			os_app += "-" + model + " Firmware";
			os_cpe += "-" + tolower( model ) + "_firmware";
			hw_app += "-" + model + " Device";
			hw_cpe += "-" + tolower( model );
			set_kb_item( name: "d-link/dsl/model", value: model );
		}
		else {
			os_app += " Unknown Model Firmware";
			os_cpe += "-unknown_model_firmware";
			hw_app += " Unknown Model Device";
			hw_cpe += "-unknown_model";
		}
		fw_ver = eregmatch( pattern: "(Firmware Version ?: |var SoftwareVersion?=\")(AU_|V|EG_|ME_)?([0-9.]+)", string: buf );
		if(fw_ver[3]){
			fw_version = fw_ver[3];
			os_cpe += ":" + fw_version;
			set_kb_item( name: "d-link/dsl/fw_version", value: fw_version );
			if(os_concl){
				os_concl += "\n";
			}
			os_concl += fw_ver[0];
		}
		if(fw_version == "unknown"){
			url2 = "/ayefeaturesconvert.js";
			req = http_get( port: port, item: url2 );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			fw_ver = eregmatch( string: res, pattern: "var AYECOM_FWVER=\"([0-9]\\.[0-9]+)\";" );
			if(fw_ver[1]){
				fw_version = fw_ver[1];
				os_cpe += ":" + fw_version;
				set_kb_item( name: "d-link/dsl/fw_version", value: fw_version );
				if(conclUrl){
					conclUrl += "\n";
				}
				conclUrl += http_report_vuln_url( port: port, url: url2, url_only: TRUE );
				if(os_concl){
					os_concl += "\n";
				}
				os_concl += fw_ver[0];
			}
		}
		if(fw_version == "unknown"){
			url2 = "/cgi-bin/login.asp";
			res = http_get_cache( port: port, item: url2 );
			fw_ver = eregmatch( pattern: "var showfwver='([0-9.]+)'", string: res );
			if(!isnull( fw_ver[1] )){
				fw_version = fw_ver[1];
				set_kb_item( name: "d-link/dsl/fw_version", value: fw_version );
				if(conclUrl){
					conclUrl += "\n";
				}
				conclUrl += http_report_vuln_url( port: port, url: url2, url_only: TRUE );
				if(os_concl){
					os_concl += "\n";
				}
				os_concl += fw_ver[0];
			}
		}
		hw_ver = eregmatch( pattern: "(>Hardware Version ?: |var HardwareVersion?=\")([0-9A-Za-z.]+)", string: buf );
		if(hw_ver[2]){
			hw_version = hw_ver[2];
			hw_cpe += ":" + tolower( hw_version );
			set_kb_item( name: "d-link/dsl/hw_version", value: hw_version );
			if(hw_concl){
				hw_concl += "\n";
			}
			hw_concl += hw_ver[0];
		}
		os_register_and_report( os: os_app, cpe: os_cpe, banner_type: "D-Link DSL Device Login Page/Banner", port: port, desc: "D-Link DSL Devices Detection", runs_key: "unixoide" );
		register_product( cpe: os_cpe, location: install, port: port, service: "www" );
		register_product( cpe: hw_cpe, location: install, port: port, service: "www" );
		report = build_detection_report( app: os_app, version: fw_version, concluded: os_concl, concludedUrl: conclUrl, install: install, cpe: os_cpe );
		report += "\n\n" + build_detection_report( app: hw_app, version: hw_version, concluded: hw_concl, install: install, cpe: hw_cpe );
		log_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 0 );

