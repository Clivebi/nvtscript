if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103689" );
	script_version( "2021-08-03T09:06:35+0000" );
	script_tag( name: "last_modification", value: "2021-08-03 09:06:35 +0000 (Tue, 03 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-04-08 13:52:56 +0200 (Mon, 08 Apr 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "D-Link DIR Devices Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "gb_hnap_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "D-LinkDIR/banner" );
	script_tag( name: "summary", value: "HTTP based detection of D-Link DIR devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
detected = FALSE;
fw_version = "unknown";
os_app = "D-Link DIR";
os_cpe = "cpe:/o:d-link:dir";
hw_version = "unknown";
hw_app = "D-Link DIR";
hw_cpe = "cpe:/h:d-link:dir";
model = "unknown";
install = "/";
if(_banner = egrep( string: banner, pattern: "(Server: Linux, (HTTP/1\\.1|WEBACCESS/1\\.0), DIR-[0-9]+[^ ]++ Ver|DIR-[0-9]+ web server)", icase: TRUE )){
	detected = TRUE;
	_banner = chomp( _banner );
	fw_concluded = _banner;
	mo = eregmatch( pattern: " DIR-([0-9]+[^ ]*)", string: _banner );
	if( mo[1] ){
		model = mo[1];
		os_app += "-" + model + " Firmware";
		os_cpe += "-" + tolower( model ) + "_firmware";
		hw_app += "-" + model + " Device";
		hw_cpe += "-" + tolower( model );
		set_kb_item( name: "d-link/dir/model", value: model );
	}
	else {
		os_app += " Unknown Model Firmware";
		os_cpe += "-unknown_model_firmware";
		hw_app += " Unknown Model Device";
		hw_cpe += "-unknown_model";
	}
	fw_ver = eregmatch( pattern: "Ver ([^\\r\\n]+)", string: _banner );
	if(fw_ver[1]){
		os_cpe += ":" + fw_ver[1];
		fw_version = fw_ver[1];
		set_kb_item( name: "d-link/dir/fw_version", value: fw_version );
	}
	buf = http_get_cache( port: port, item: "/" );
	hw_ver = eregmatch( pattern: "Hardware Version : (<span class=\"value\" style=\"text-transform:uppercase;\">)?([^ <]+)<", string: buf );
	if( hw_ver[2] ){
		hw_version = hw_ver[2];
	}
	else {
		hw_ver = eregmatch( pattern: "class=\"(hwv|hwversion)\">.*([ABCDEIT][12])<", string: buf );
		if(hw_ver[2]){
			hw_version = hw_ver[2];
		}
	}
	if(hw_version != "unknown"){
		hw_cpe += ":" + tolower( hw_version );
		set_kb_item( name: "d-link/dir/hw_version", value: hw_version );
		hw_concluded = hw_ver[0];
		hw_conclurl = http_report_vuln_url( port: port, url: "/", url_only: TRUE );
	}
}
if(ContainsString( banner, "Server: Mathopd/" )){
	url = "/";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "<title>D-LINK" ) && !ContainsString( buf, "LOGIN_USER" )){
		url = "/index_temp.php";
		buf = http_get_cache( item: url, port: port );
	}
	if(!ContainsString( buf, "<title>D-LINK" ) && !ContainsString( buf, "LOGIN_USER" )){
		exit( 0 );
	}
	detected = TRUE;
	mo = eregmatch( pattern: "class=l_tb>DIR-([^ <]+)<", string: buf );
	if( mo[1] ){
		model = mo[1];
		fw_concluded = mo[0];
		os_app += "-" + model + " Firmware";
		os_cpe += "-" + tolower( model ) + "_firmware";
		hw_app += "-" + model + " Device";
		hw_cpe += "-" + tolower( model );
		set_kb_item( name: "d-link/dir/model", value: model );
	}
	else {
		os_app += " Unknown Model Firmware";
		os_cpe += "-unknown_model_firmware";
		hw_app += " Unknown Model Device";
		hw_cpe += "-unknown_model";
	}
	fw_ver = eregmatch( pattern: ">Firmware Version&nbsp;:&nbsp;([0-9A-Z.]+)&nbsp;<", string: buf );
	if( fw_ver[1] ){
		fw_version = fw_ver[1];
	}
	else {
		fw_ver = eregmatch( pattern: "<td noWrap align=\"right\">[^<]+&nbsp;:&nbsp;([0-9A-Z.]+)&nbsp;</td>", string: buf );
		if(fw_ver[1]){
			fw_version = fw_ver[1];
		}
	}
	if(fw_version != "unknown"){
		os_cpe += ":" + fw_version;
		set_kb_item( name: "d-link/dir/fw_version", value: fw_version );
		if(fw_concluded){
			fw_concluded += "\n";
		}
		fw_concluded += fw_ver[0];
		fw_conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	hw_ver = eregmatch( pattern: "Hardware Version.*([ABCDEINT][124x]+)(</|&nbsp;)", string: buf );
	if( hw_ver[1] ){
		hw_version = hw_ver[1];
	}
	else {
		hw_ver = eregmatch( pattern: "<td noWrap align=\"right\">[^<]+&nbsp;:&nbsp;rev ([A-Z0-9]+)(</td>|&nbsp;</td>)", string: buf );
		if(hw_ver[1]){
			hw_version = hw_ver[1];
		}
	}
	if(hw_version != "unknown"){
		hw_cpe += ":" + tolower( hw_version );
		set_kb_item( name: "d-link/dir/hw_version", value: hw_version );
		hw_concluded = hw_ver[0];
		hw_conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
}
if(ContainsString( banner, "Server: mini_httpd" )){
	url = "/cgi-bin/webproc";
	buf = http_get_cache( port: port, item: url );
	if(ContainsString( buf, "target=\"_blank\">DIR-" ) && ContainsString( buf, "DIV_ProductPage" )){
		detected = TRUE;
		mo = eregmatch( pattern: "target=\"_blank\">DIR-([0-9A-Z]+)<", string: buf );
		if(!isnull( mo[1] )){
			model = mo[1];
		}
		if( model != "unknown" ){
			fw_concluded = mo[0];
			os_app += "-" + model + " Firmware";
			os_cpe += "-" + tolower( model ) + "_firmware";
			hw_app += "-" + model + " Device";
			hw_cpe += "-" + tolower( model );
			set_kb_item( name: "d-link/dir/model", value: model );
		}
		else {
			os_app += " Unknown Model Firmware";
			os_cpe += "-unknown_model_firmware";
			hw_app += " Unknown Model Device";
			hw_cpe += "-unknown_model";
		}
		fw_ver = eregmatch( pattern: "Firmware Version : </span>[^>]+>([0-9a-zA-Z.]+)<", string: buf );
		if(fw_ver[1]){
			fw_version = fw_ver[1];
		}
		if(fw_version != "unknown"){
			os_cpe += ":" + fw_version;
			set_kb_item( name: "d-link/dir/fw_version", value: fw_version );
			if(fw_concluded){
				fw_concluded += "\n";
			}
			fw_concluded += fw_ver[0];
			fw_conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		hw_ver = eregmatch( pattern: "Hardware Version : </span>[^>]+>([ABCDEIT][12])<", string: buf );
		if(hw_ver[1]){
			hw_version = hw_ver[1];
		}
		if(hw_version != "unknown"){
			hw_cpe += ":" + tolower( hw_version );
			set_kb_item( name: "d-link/dir/hw_version", value: hw_version );
			hw_concluded = hw_ver[0];
			hw_conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
	}
}
if(ContainsString( banner, "Server: WebServer" ) || ContainsString( banner, "Server: lighttpd" )){
	url = "/";
	buf = http_get_cache( port: port, item: url );
	if(ContainsString( buf, "<title>D-LINK" ) && ( IsMatchRegexp( buf, "Model Name.+DIR-" ) || ( IsMatchRegexp( buf, "Product Page.+DIR-" ) && ContainsString( buf, "Firmware Version" ) && ContainsString( buf, "Hardware Version" ) ) || ( IsMatchRegexp( buf, "show_words[(]TA2[)].+DIR-" ) && IsMatchRegexp( buf, "show_words[(]TA3[)]" ) && IsMatchRegexp( buf, "show_words[(]sd_FWV[)]" ) ) || ( IsMatchRegexp( buf, "class=\"product\".+DIR-" ) && IsMatchRegexp( buf, "class=\"hwversion\"" ) && IsMatchRegexp( buf, "class=\"version\"" ) ) )){
		detected = TRUE;
		mo = eregmatch( pattern: "class=(l_tb|\"modelname\")>DIR-([0-9A-Z]+)<", string: buf );
		if(mo[2]){
			model = mo[2];
		}
		if(model == "unknown"){
			mo = eregmatch( pattern: "\"Model Name\"\\);</script>[ ]?: DIR-([0-9A-Z]+)<", string: buf );
			if(mo[1]){
				model = mo[1];
			}
		}
		if(model == "unknown"){
			mo = eregmatch( pattern: "<div class=\"pp\">Product Page[ ]?: DIR-([0-9A-Z]+)<", string: buf );
			if(mo[1]){
				model = mo[1];
			}
		}
		if(model == "unknown"){
			mo = eregmatch( pattern: "show_words[(]TA2[)]</script>.+DIR-([0-9A-Z]+)", string: buf );
			if(mo[1]){
				model = mo[1];
			}
		}
		if(model == "unknown"){
			mo = eregmatch( pattern: "class=\"product\".+DIR-([0-9A-Z]+)", string: buf );
			if(mo[1]){
				model = mo[1];
			}
		}
		if( model != "unknown" ){
			fw_concluded = mo[0];
			os_app += "-" + model + " Firmware";
			os_cpe += "-" + tolower( model ) + "_firmware";
			hw_app += "-" + model + " Device";
			hw_cpe += "-" + tolower( model );
			set_kb_item( name: "d-link/dir/model", value: model );
		}
		else {
			os_app += " Unknown Model Firmware";
			os_cpe += "-unknown_model_firmware";
			hw_app += " Unknown Model Device";
			hw_cpe += "-unknown_model";
		}
		fw_ver = eregmatch( pattern: "Firmware Version : ([0-9a-zA-Z.]+)<", string: buf );
		if(fw_ver[1]){
			fw_version = fw_ver[1];
		}
		if(fw_version == "unknown"){
			fw_ver = eregmatch( pattern: "\"Firmware Version\"\\);</script> : ([0-9a-zA-Z.]+)</td>", string: buf );
			if(fw_ver[1]){
				fw_version = fw_ver[1];
			}
		}
		if(fw_version == "unknown"){
			fw_ver = eregmatch( pattern: "show_words\\(sd_FWV\\)</script>[A-Za-z ]*: ([0-9a-zA-Z.]+)", string: buf );
			if(fw_ver[1]){
				fw_version = fw_ver[1];
			}
		}
		if(fw_version == "unknown"){
			fw_ver = eregmatch( pattern: "<span class=\"version\">[^:]+:[^0-9A-Z]*([0-9a-zA-Z.]+)<\\/span", string: buf );
			if(fw_ver[1]){
				fw_version = fw_ver[1];
			}
		}
		if(fw_version != "unknown"){
			os_cpe += ":" + fw_version;
			set_kb_item( name: "d-link/dir/fw_version", value: fw_version );
			if(fw_concluded){
				fw_concluded += "\n";
			}
			fw_concluded += fw_ver[0];
			fw_conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		hw_ver = eregmatch( pattern: "Hardware Version.*([ABCDEIT][12])(</?|&nbsp;)", string: buf );
		if(hw_ver[1]){
			hw_version = hw_ver[1];
		}
		if(hw_version == "unknown"){
			hw_ver = eregmatch( pattern: "\"Hardware Version\"\\);</script> : ([^<]+)</td>", string: buf );
			if(hw_ver[1]){
				hw_version = hw_ver[1];
			}
		}
		if(hw_version == "unknown"){
			hw_ver = eregmatch( pattern: "show_words[(]TA3[)]</script>[A-Za-z ]*: ([0-9A-Z.]+)", string: buf );
			if(hw_ver[1]){
				hw_version = hw_ver[1];
			}
		}
		if(hw_version == "unknown"){
			hw_ver = eregmatch( pattern: "<span class=\"hwversion\">.*[:>] ?([0-9A-Z.]+)<\\/span", string: buf );
			if(hw_ver[1]){
				hw_version = hw_ver[1];
			}
		}
		if(hw_version != "unknown"){
			hw_cpe += ":" + tolower( hw_version );
			set_kb_item( name: "d-link/dir/hw_version", value: hw_version );
			hw_concluded = hw_ver[0];
			hw_conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
	}
}
if(IsMatchRegexp( banner, "Location:.+dir_login\\.asp" )){
	url = "/dir_login.asp";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "Ver='DIR-[0-9]+" ) || IsMatchRegexp( buf, "Product Page:.+ DIR-[0-9A-Z]+" )){
		detected = TRUE;
		mo = eregmatch( string: buf, pattern: "Product Page ?: ?DIR-([0-9A-Z]+)" );
		if(mo[1]){
			model = mo[1];
		}
		if(model == "unknown"){
			mo = eregmatch( string: buf, pattern: "Ver ?= ?'DIR-([0-9A-Z]+)'" );
			if(mo[1]){
				model = mo[1];
			}
		}
		if( model != "unknown" ){
			w_concluded = mo[0];
			os_app += "-" + model + " Firmware";
			os_cpe += "-" + tolower( model ) + "_firmware";
			hw_app += "-" + model + " Device";
			hw_cpe += "-" + tolower( model );
			set_kb_item( name: "d-link/dir/model", value: model );
		}
		else {
			os_app += " Unknown Model Firmware";
			os_cpe += "-unknown_model_firmware";
			hw_app += " Unknown Model Device";
			hw_cpe += "-unknown_model";
		}
		fw_ver = eregmatch( pattern: "Firmware Version ?: ?([0-9a-zA-Z.]+)<", string: buf );
		if(fw_ver[1]){
			fw_version = fw_ver[1];
		}
		if(fw_version == "unknown"){
			fw_ver = eregmatch( pattern: "FirmwareVer ?= ?[\"\']([0-9a-zA-Z.]+)[\"\']", string: buf );
			if(fw_ver[1]){
				fw_version = fw_ver[1];
			}
		}
		if(fw_version != "unknown"){
			os_cpe += ":" + fw_version;
			set_kb_item( name: "d-link/dir/fw_version", value: fw_version );
			if(fw_concluded){
				fw_concluded += "\n";
			}
			fw_concluded += fw_ver[0];
			fw_conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		hw_ver = eregmatch( pattern: "Hardware Version.*([ABCDEIT][12])(</?| )", string: buf );
		if(hw_ver[1]){
			hw_version = hw_ver[1];
		}
		if(hw_version == "unknown"){
			hw_ver = eregmatch( pattern: "HardwareVer ?= ?[\"\']([0-9A-Z]+)[\"\']", string: buf );
			if(hw_ver[1]){
				hw_version = hw_ver[1];
			}
		}
		if(hw_version != "unknown"){
			hw_cpe += ":" + tolower( hw_version );
			set_kb_item( name: "d-link/dir/hw_version", value: hw_version );
			hw_concluded = hw_ver[0];
			hw_conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
	}
}
if(!detected){
	if(!get_kb_item( "HNAP/" + port + "/detected" )){
		exit( 0 );
	}
	vendor = get_kb_item( "HNAP/" + port + "/vendor" );
	if(!vendor || vendor != "D-Link"){
		exit( 0 );
	}
	hnap_model = get_kb_item( "HNAP/" + port + "/model" );
	if(!hnap_model || !IsMatchRegexp( hnap_model, "^DIR-" )){
		exit( 0 );
	}
	detected = TRUE;
	mo = eregmatch( pattern: "^DIR-(.+)", string: hnap_model );
	if( mo[1] ){
		model = mo[1];
		hnap_mod_concl = get_kb_item( "HNAP/" + port + "/model_concluded" );
		if(hnap_mod_concl && strlen( hnap_mod_concl ) > 0){
			fw_concluded = hnap_mod_concl;
		}
		os_app += "-" + model + " Firmware";
		os_cpe += "-" + tolower( model ) + "_firmware";
		hw_app += "-" + model + " Device";
		hw_cpe += "-" + tolower( model );
		set_kb_item( name: "d-link/dir/model", value: model );
	}
	else {
		os_app += " Unknown Model Firmware";
		os_cpe += "-unknown_model_firmware";
		hw_app += " Unknown Model Device";
		hw_cpe += "-unknown_model";
	}
	hnap_fw = get_kb_item( "HNAP/" + port + "/firmware" );
	fw_ver = eregmatch( pattern: "^(.+)", string: hnap_fw );
	if(fw_ver[1]){
		os_cpe += ":" + fw_ver[1];
		fw_version = fw_ver[1];
		set_kb_item( name: "d-link/dir/fw_version", value: fw_version );
		hnap_fw_concl = get_kb_item( "HNAP/" + port + "/firmware_concluded" );
		if(hnap_fw_concl && strlen( hnap_fw_concl ) > 0){
			if(fw_concluded){
				fw_concluded += "\n";
			}
			fw_concluded += hnap_fw_concl;
		}
	}
	hnap_hw = get_kb_item( "HNAP/" + port + "/hardware" );
	hw_ver = eregmatch( pattern: "^(.+)", string: hnap_hw );
	if(hw_ver[1]){
		hw_version = hw_ver[1];
		hw_cpe += ":" + tolower( hw_version );
		set_kb_item( name: "d-link/dir/hw_version", value: hw_version );
		hnap_hw_concl = get_kb_item( "HNAP/" + port + "/hardware_concluded" );
		if(hnap_hw_concl && strlen( hnap_hw_concl ) > 0){
			hw_concluded += hnap_hw_concl;
		}
	}
	hnap_conclurl = get_kb_item( "HNAP/" + port + "/conclurl" );
	if(hnap_conclurl && strlen( hnap_conclurl ) > 0){
		fw_conclurl = hnap_conclurl;
		hw_conclurl = hnap_conclurl;
	}
}
if(detected){
	set_kb_item( name: "Host/is_dlink_dir_device", value: TRUE );
	set_kb_item( name: "Host/is_dlink_device", value: TRUE );
	os_register_and_report( os: os_app, cpe: os_cpe, banner_type: "D-Link DIR Device Banner / Login Page", port: port, desc: "D-Link DIR Devices Detection", runs_key: "unixoide" );
	register_product( cpe: os_cpe, location: install, port: port, service: "www" );
	register_product( cpe: hw_cpe, location: install, port: port, service: "www" );
	report = build_detection_report( app: os_app, version: fw_version, concluded: fw_concluded, concludedUrl: fw_conclurl, install: install, cpe: os_cpe );
	report += "\n\n" + build_detection_report( app: hw_app, version: hw_version, concluded: hw_concluded, concludedUrl: hw_conclurl, install: install, cpe: hw_cpe );
	log_message( port: port, data: report );
}
exit( 0 );

