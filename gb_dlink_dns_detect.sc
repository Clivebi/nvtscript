if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106015" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-07-10 14:32:27 +0700 (Fri, 10 Jul 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "D-Link DNS NAS Devices Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "D-LinkDNS/banner" );
	script_tag( name: "summary", value: "Detection of D-Link DNS NAS Devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is a D-Link DNS NAS device from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
fw_version = "unknown";
os_app = "D-Link DNS";
os_cpe = "cpe:/o:d-link:dns";
hw_version = "unknown";
hw_app = "D-Link DNS";
hw_cpe = "cpe:/h:d-link:dns";
model = "unknown";
install = "/";
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if( ContainsString( banner, "Server: lighttpd/" ) ){
	res = http_get_cache( item: "/", port: port );
	if(!res){
		exit( 0 );
	}
	logo_identified = FALSE;
	logo_url = "/web/images/logo.png";
	if(ContainsString( res, logo_url )){
		req = http_get( item: logo_url, port: port );
		res2 = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(res2 && hexstr( MD5( res2 ) ) == "0b5e6b0092c45768fbca24706bc9e08d"){
			logo_identified = TRUE;
		}
	}
	if(ContainsString( res, "Please Select Your Account" ) && ( ContainsString( res, "ShareCenter" ) || logo_identified )){
		found = TRUE;
		url = "/xml/info.xml";
		res = http_get_cache( item: url, port: port );
		if(!res || !IsMatchRegexp( res, "<info>" ) || !IsMatchRegexp( res, "www\\.dlink\\.com" )){
			url = "//xml/info.xml";
			res = http_get_cache( item: url, port: port );
		}
		if(IsMatchRegexp( res, "<info>" ) && IsMatchRegexp( res, "www\\.dlink\\.com" )){
			mo = eregmatch( pattern: "<hw_ver>DNS-(.*)</hw_ver>", string: res );
			if( mo[1] ){
				model = mo[1];
				concluded = mo[0];
				os_app += "-" + model + " Firmware";
				os_cpe += "-" + tolower( model ) + "_firmware";
				hw_app += "-" + model + " Device";
				hw_cpe += "-" + tolower( model );
				set_kb_item( name: "d-link/dns/model", value: model );
			}
			else {
				os_app += " Unknown Model Firmware";
				os_cpe += "-unknown_model_firmware";
				hw_app += " Unknown Model Device";
				hw_cpe += "-unknown_model";
			}
			fw_ver = eregmatch( pattern: "<version>(.*)</version>", string: res );
			if(fw_ver[1]){
				os_cpe += ":" + fw_ver[1];
				fw_version = fw_ver[1];
				set_kb_item( name: "d-link/dns/fw_version", value: fw_version );
				if(concluded){
					concluded += "\n";
				}
				concluded += fw_ver[0];
			}
			if(fw_version != "unknown" || model != "unknown"){
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		if(model == "unknown"){
			os_app += " Unknown Model Firmware";
			os_cpe += "-unknown_model_firmware";
			hw_app += " Unknown Model Device";
			hw_cpe += "-unknown_model";
		}
	}
}
else {
	if(ContainsString( banner, "Server: GoAhead-Webs" )){
		res = http_get_cache( item: "/web/login.asp", port: port );
		if(egrep( string: res, pattern: "<TITLE>dlink(.*)?</TITLE>", icase: TRUE ) && ContainsString( res, "D-Link Corporation/D-Link Systems, Inc." )){
			found = TRUE;
			os_app += " Unknown Model Firmware";
			os_cpe += "-unknown_model_firmware";
			hw_app += " Unknown Model Device";
			os_cpe += "-unknown_model";
		}
	}
}
if(found){
	set_kb_item( name: "Host/is_dlink_dns_device", value: TRUE );
	set_kb_item( name: "Host/is_dlink_device", value: TRUE );
	os_register_and_report( os: os_app, cpe: os_cpe, banner_type: "D-Link DNS Device Login Page", port: port, desc: "D-Link DNS Devices Detection", runs_key: "unixoide" );
	register_product( cpe: os_cpe, location: install, port: port, service: "www" );
	register_product( cpe: hw_cpe, location: install, port: port, service: "www" );
	report = build_detection_report( app: os_app, version: fw_version, concludedUrl: conclUrl, concluded: concluded, install: install, cpe: os_cpe );
	report += "\n\n" + build_detection_report( app: hw_app, skip_version: TRUE, install: install, cpe: hw_cpe );
	log_message( port: port, data: report );
}
exit( 0 );

