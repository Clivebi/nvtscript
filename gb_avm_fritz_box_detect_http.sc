if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108036" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-01-05 13:21:05 +0100 (Thu, 05 Jan 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "AVM FRITZ!Box Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script attempts to identify an AVM FRITZ!Box via the HTTP
  login page and tries to extract the model and version number." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
fingerprint["a39b0868ecce7916673a3119c164a268"] = "Fon WLAN;7240";
fingerprint["4ff79300a437d947adce1ecbc5dbcfe9"] = "Fon WLAN;7170";
fingerprint["9adfbf40db1a7594be31c21f28767363"] = "Fon WLAN;7270";
port = http_get_port( default: 80 );
buf = http_get_cache( item: "/", port: port );
if(ContainsString( buf, "FRITZ!Box" ) && ( ContainsString( buf, "AVM" ) || ContainsString( buf, "logincheck.lua" ) || ContainsString( buf, "/cgi-bin/webcm" ) ) && !ContainsString( buf, "\"GUI_IS_POWERLINE\":true" ) && !ContainsString( buf, "FRITZ!Powerline" ) && !ContainsString( buf, "\"GUI_IS_REPEATER\":true" ) && !ContainsString( buf, "FRITZ!WLAN Repeater" )){
	set_kb_item( name: "avm_fritz_box/detected", value: TRUE );
	set_kb_item( name: "avm_fritz_box/http/detected", value: TRUE );
	set_kb_item( name: "avm_fritz_box/http/port", value: port );
	type = "unknown";
	model = "unknown";
	fw_version = "unknown";
	mo = eregmatch( pattern: "FRITZ!Box (Fon WLAN|WLAN)? ?([0-9]+( (v[0-9]+|vDSL|SL|LTE|Cable))?)", string: buf );
	if(!isnull( mo[1] )){
		type = mo[1];
	}
	if(!isnull( mo[2] )){
		model = mo[2];
	}
	if(type == "unknown" && model == "unknown"){
		req = http_get( port: port, item: "/css/default/images/kopfbalken_mitte.gif" );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(!isnull( res )){
			md5 = hexstr( MD5( res ) );
			if(fingerprint[md5]){
				tmp = split( buffer: fingerprint[md5], sep: ";", keep: FALSE );
				type = tmp[0];
				model = tmp[1];
			}
		}
	}
	if(type == "unknown" && model == "unknown"){
		time = unixtime();
		postdata = "getpage=..%2Fhtml%2Fde%2Fmenus%2Fmenu2.html&errorpage=..%2Fhtml%2Findex.html" + "&var%3Alang=de&var%3Apagename=home&var%3Amenu=home" + "&time%3Asettings%2Ftime=" + time + "%2C-60";
		req = http_post_put_req( port: port, url: "/cgi-bin/webcm", data: postdata, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded", "Upgrade-Insecure-Requests", "1", "Referer", http_report_vuln_url( port: port, url: "/cgi-bin/webcm", url_only: TRUE ) ) );
		res = http_send_recv( port: port, data: req );
		if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<p class=\"ac\">FRITZ!Box" )){
			mo = eregmatch( pattern: "\"ac\">FRITZ!Box ([^\\(,]+).*Firmware-Version ([0-9.]+)<", string: res );
			if(!isnull( mo[1] )){
				mo_nd_type = eregmatch( pattern: "FRITZ!Box (Fon WLAN|WLAN|Fon)? ?([0-9]+( (v[0-9]+|vDSL|SL|LTE|Cable))?)?", string: mo[0] );
				if(!isnull( mo_nd_type[1] )){
					type = mo_nd_type[1];
				}
				if(!isnull( mo_nd_type[2] )){
					model = mo_nd_type[2];
				}
			}
			if(!isnull( mo[2] )){
				fw_version = mo[2];
			}
		}
	}
	if(fw_version == "unknown"){
		fw = eregmatch( pattern: "%26version%3D([0-9.]+)%26subversion%3D", string: buf );
		if(!isnull( fw[1] )){
			fw_version = fw[1];
		}
	}
	set_kb_item( name: "avm_fritz_box/http/" + port + "/type", value: type );
	set_kb_item( name: "avm_fritz_box/http/" + port + "/model", value: model );
	set_kb_item( name: "avm_fritz_box/http/" + port + "/firmware_version", value: fw_version );
}
exit( 0 );

