if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103675" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-03-07 14:31:24 +0100 (Thu, 07 Mar 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "HP Printer Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of HP Printers.

  The script sends a connection request to the remote host and
  attempts to detect if the remote host is a HP printer." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("hp_printers.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
urls = get_hp_detect_urls();
for url in keys( urls ) {
	pattern = urls[url];
	url = ereg_replace( string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "" );
	buf = http_get_cache( item: url, port: port );
	if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
		continue;
	}
	if(match = eregmatch( pattern: pattern, string: buf, icase: TRUE )){
		if(isnull( match[1] )){
			continue;
		}
		if( !isnull( match[5] ) ) {
			model = match[5];
		}
		else {
			if( !isnull( match[4] ) ) {
				model = match[4];
			}
			else {
				if( !isnull( match[3] ) ) {
					model = match[3];
				}
				else {
					if( isnull( match[3] ) && !isnull( match[2] ) ) {
						model = match[2];
					}
					else {
						model = match[1];
					}
				}
			}
		}
		if(!model){
			continue;
		}
		model = chomp( model );
		if(ContainsString( buf, "Server: HP HTTP Server" )){
			version = eregmatch( pattern: "Server: HP HTTP Server.*\\{([^},]+).*\\}[\r\n]+", string: buf );
			if(!isnull( version[1] )){
				fw_ver = version[1];
				concUrl = url;
			}
		}
		if(ContainsString( buf, "<strong id=\"FirmwareRevision\">" )){
			version = eregmatch( pattern: "<strong id=\"FirmwareRevision\">([0-9_]*)", string: buf );
			if(!isnull( version[1] )){
				fw_ver = version[1];
				concUrl = url;
			}
		}
		if(isnull( fw_ver )){
			url = "/jd_diag.htm";
			res = http_get_cache( item: url, port: port );
			version = eregmatch( pattern: "([A-Z0-9_]{9,}[.]{1}[0-9]+)", string: res );
			if(!isnull( version[1] )){
				fw_ver = version[1];
				concUrl = url;
			}
		}
		if(isnull( fw_ver )){
			url = "/hp/device/webAccess/index.htm?content=auto_firmware_update_manifest";
			res = http_get_cache( item: url, port: port );
			version = eregmatch( pattern: "<b>Firmware version:&nbsp;</b>([A-Z0-9_.]+)<br/><b>Published:", string: res );
			if(!isnull( version[1] )){
				fw_ver = version[1];
				concUrl = url;
			}
		}
		if(isnull( fw_ver )){
			url = "/DevMgmt/ProductConfigDyn.xml";
			res = http_get_cache( item: url, port: port );
			version = eregmatch( pattern: "<prdcfgdyn:ProductInformation>.*<dd:Revision>([^>]+)</dd:Revision>", string: res );
			if(!isnull( version[1] )){
				fw_ver = version[1];
				concUrl = url;
			}
		}
		if(isnull( fw_ver )){
			url = "/info_configuration.html";
			res = http_get_cache( item: url, port: port );
			version = eregmatch( pattern: ">Firmware Datecode:</td>[^>]+>([^<]+)</td>", string: res );
			if(!isnull( version[1] )){
				fw_ver = version[1];
				concUrl = url;
			}
		}
		set_kb_item( name: "hp_printer/installed", value: TRUE );
		set_kb_item( name: "hp_printer/port", value: port );
		set_kb_item( name: "hp_model", value: model );
		if(fw_ver){
			set_kb_item( name: "hp_fw_ver", value: fw_ver );
		}
		cpe_model = tolower( model );
		cpe = "cpe:/h:hp:" + cpe_model;
		cpe = str_replace( string: cpe, find: " ", replace: "_" );
		if(fw_ver){
			cpe += ":" + fw_ver;
		}
		register_product( cpe: cpe, location: "/", port: port, service: "www" );
		report = "The remote Host is a HP " + model + " printer device.\n\n";
		if(fw_ver){
			report += "Firmware version: " + fw_ver + "\n";
		}
		report += "CPE:              " + cpe + "\n\n";
		report += "Concluded:        " + match[0] + "\n";
		report += "ConcludedURL:     " + http_report_vuln_url( port: port, url: concUrl, url_only: TRUE );
		log_message( data: report, port: port );
		pref = get_kb_item( "global_settings/exclude_printers" );
		if(pref == "yes"){
			log_message( port: port, data: "The remote host is a printer. The scan has been disabled against this host.\nIf you want to scan the remote host, uncheck the \"Exclude printers from scan\" option and re-scan it." );
			set_kb_item( name: "Host/dead", value: TRUE );
		}
		exit( 0 );
	}
}
exit( 0 );

