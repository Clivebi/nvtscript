if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141679" );
	script_version( "2021-07-02T06:34:34+0000" );
	script_tag( name: "last_modification", value: "2021-07-02 06:34:34 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "creation_date", value: "2018-11-13 12:55:06 +0700 (Tue, 13 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Western Digital My Book Live Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Western Digital My Book Live devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.wd.com" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
res1 = http_get_cache( port: port, item: "/UI/" );
res2 = http_get_cache( port: port, item: "/UI/login" );
if(( ContainsString( res1, "<title>MY BOOK&reg; LIVE&trade;</title>" ) && ContainsString( res1, "device_rebooting_text" ) ) || ( ContainsString( res2, "<title>MY BOOK&reg; LIVE&trade;</title>" ) && ContainsString( res2, "=\"LoginOwnerPasswd\">" ) )){
	version = "unknown";
	install = "/";
	base_os_cpe = "cpe:/o:western_digital:my_book_live_firmware";
	hw_cpe = "cpe:/h:western_digital:my_book_live";
	hw_name = "Western Digital My Book Live";
	os_name = hw_name + " Firmware";
	url = "/UI/settings/system";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "Version:</label>MyBookLive  ([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		concl = vers[0];
		version = vers[1];
		conclurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	set_kb_item( name: "wd/product/detected", value: TRUE );
	set_kb_item( name: "western_digital/mybook_live/detected", value: TRUE );
	set_kb_item( name: "western_digital/mybook_live/http/detected", value: TRUE );
	os_cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: base_os_cpe + ":" );
	if(!os_cpe){
		os_cpe = base_os_cpe;
	}
	register_product( cpe: os_cpe, location: install, port: port, service: "www" );
	register_product( cpe: hw_cpe, location: install, port: port, service: "www" );
	os_register_and_report( os: os_name, cpe: os_cpe, desc: "Western Digital My Book Live Detection (HTTP)", runs_key: "unixoide" );
	report = build_detection_report( app: os_name, version: version, install: install, cpe: os_cpe );
	report += "\n\n";
	report += build_detection_report( app: hw_name, skip_version: TRUE, install: install, cpe: hw_cpe );
	if(concl){
		report += "\n\n";
		report += "Concluded from version/product identification result:\n\n" + concl + "\n\n";
		report += "Concluded from version/product identification location:\n\n" + conclurl;
	}
	log_message( port: port, data: report );
}
exit( 0 );

