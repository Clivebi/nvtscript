if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111090" );
	script_version( "2021-03-25T07:04:23+0000" );
	script_tag( name: "last_modification", value: "2021-03-25 07:04:23 +0000 (Thu, 25 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-03-17 10:42:39 +0100 (Thu, 17 Mar 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Proxmox Virtual Environment (VE, PVE) Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 3128, 8006 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Proxmox Virtual Environment (VE, PVE)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8006 );
banner = http_get_remote_headers( port: port );
res = http_get_cache( item: "/", port: port );
detection_patterns = make_list( "^Server\\s*:\\s*pve-api-daemon",
	 "<title>[^>]*Proxmox Virtual Environment</title>",
	 "\"/pve2/(css/ext([0-9])?-pve\\.css|js/pvemanagerlib\\.js)",
	 "PVE\\.UserName",
	 "PVE\\.CSRFPreventionToken",
	 "\"boxheadline\">Proxmox Virtual Environment ",
	 "'PVEAuthCookie'" );
found = 0;
concluded = "";
for pattern in detection_patterns {
	if( ContainsString( pattern, "pve-api-daemon" ) ) {
		concl = egrep( string: banner, pattern: pattern, icase: TRUE );
	}
	else {
		concl = egrep( string: res, pattern: pattern, icase: FALSE );
	}
	if(concl){
		if(concluded){
			concluded += "\n";
		}
		concl = chomp( concl );
		concl = ereg_replace( string: concl, pattern: "^(\\s+)", replace: "" );
		concluded += "    " + concl;
		if( ContainsString( pattern, "pve-api-daemon" ) ) {
			found += 2;
		}
		else {
			found++;
		}
	}
}
if(found > 1){
	version = "unknown";
	set_kb_item( name: "proxmox/ve/detected", value: TRUE );
	set_kb_item( name: "proxmox/ve/http/detected", value: TRUE );
	set_kb_item( name: "proxmox/ve/http/port", value: port );
	ver = eregmatch( pattern: "\"boxheadline\">Proxmox Virtual Environment ([0-9.]+)</a>", string: res );
	if(ver[1]){
		version = ver[1];
	}
	if(version == "unknown"){
		ver = eregmatch( pattern: "\"/pve2/(css/ext([0-9])?-pve\\.css|js/pvemanagerlib\\.js)\\?ver=([0-9.-]+)\"", string: res );
		if(ver[3]){
			version = ver[3];
		}
	}
	if(version == "unknown"){
		url = "/pve-docs/pve-admin-guide.html";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		ver = eregmatch( pattern: ">version ([0-9.]+)", string: res );
		if(ver[1]){
			version = ver[1];
			concl_url = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			concluded += "\n    " + chomp( ver[0] );
		}
	}
	set_kb_item( name: "proxmox/ve/http/" + port + "/version", value: version );
	set_kb_item( name: "proxmox/ve/http/" + port + "/concluded", value: concluded );
	if(concl_url){
		set_kb_item( name: "proxmox/ve/http/" + port + "/concludedUrl", value: "    " + concl_url );
	}
}
exit( 0 );

