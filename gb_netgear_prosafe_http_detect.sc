if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108308" );
	script_version( "2021-06-29T07:38:55+0000" );
	script_tag( name: "last_modification", value: "2021-06-29 07:38:55 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-12-05 09:03:31 +0100 (Tue, 05 Dec 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "NETGEAR ProSAFE Devices Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of NETGEAR ProSAFE devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url1 = "/";
url2 = "/login.htm";
url3 = "/login_new.asp";
buf = http_get_cache( item: url1, port: port );
buf2 = http_get_cache( item: url2, port: port );
buf3 = http_get_cache( item: url3, port: port );
if(ContainsString( buf, "<title>NETGEAR ProSAFE" ) || ContainsString( buf, "<title>Netgear Prosafe" ) || ContainsString( buf, "<div class=\"switchInfo\">.*ProSAFE.*</div>" ) || ( egrep( pattern: "<title>netgear", string: buf, icase: TRUE ) && ( ContainsString( buf, "/base/images/netgear_" ) || ContainsString( buf, "/base/netgear_login.html" ) || IsMatchRegexp( buf, "<td>Copyright &copy; .* Netgear &reg;</td>" ) || ContainsString( buf, "login.cgi" ) ) ) || ( ContainsString( buf2, "<title>Netgear ProSAFE" ) || ContainsString( buf2, "<title>Netgear Prosafe" ) ) || ( ContainsString( buf3, "ProSAFE" ) && ContainsString( buf3, "<TITLE>NETGEAR" ) )){
	model = "unknown";
	fw_version = "unknown";
	fw_build = "unknown";
	mod = eregmatch( pattern: "<div class=\"switchInfo\">([0-9a-zA-Z\\-]+)[^\r\n]+</div>", string: buf, icase: TRUE );
	if( mod[1] ){
		model = mod[1];
		set_kb_item( name: "netgear/prosafe/http/" + port + "/concluded", value: mod[0] );
		set_kb_item( name: "netgear/prosafe/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url1, url_only: TRUE ) );
	}
	else {
		mod = eregmatch( pattern: "/base/images/netgear_([0-9a-zA-Z\\\\-]+)_banner.gif", string: buf, icase: TRUE );
		if( mod[1] ){
			model = mod[1];
			set_kb_item( name: "netgear/prosafe/http/" + port + "/concluded", value: mod[0] );
			set_kb_item( name: "netgear/prosafe/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url1, url_only: TRUE ) );
		}
		else {
			mod = eregmatch( pattern: "<TITLE>NetGear ([0-9a-zA-Z\\\\-]+)</TITLE>", string: buf, icase: TRUE );
			if( mod[1] ){
				model = mod[1];
				set_kb_item( name: "netgear/prosafe/http/" + port + "/concluded", value: mod[0] );
				set_kb_item( name: "netgear/prosafe/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url1, url_only: TRUE ) );
			}
			else {
				mod = eregmatch( pattern: "sysGeneInfor = '([^?]+)[^']+", string: buf2 );
				if( mod[1] ){
					model = mod[1];
					set_kb_item( name: "netgear/prosafe/http/" + port + "/concluded", value: mod[0] );
					set_kb_item( name: "netgear/prosafe/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url2, url_only: TRUE ) );
					sysinfo = split( buffer: mod[0], sep: "?", keep: FALSE );
					if(!isnull( sysinfo[3] )){
						fw_version = sysinfo[3];
					}
					if(!isnull( sysinfo[2] )){
						register_host_detail( name: "MAC", value: tolower( sysinfo[2] ), desc: "NETGEAR ProSAFE Devices Detection (HTTP)" );
						replace_kb_item( name: "Host/mac_address", value: tolower( sysinfo[2] ) );
					}
				}
				else {
					mod = eregmatch( pattern: "\"productName\">[^A-Z]+([^ ]+)[^\r\n]+", string: buf3 );
					if(mod[1]){
						model = mod[1];
						set_kb_item( name: "netgear/prosafe/http/" + port + "/concluded", value: mod[0] );
						set_kb_item( name: "netgear/prosafe/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url3, url_only: TRUE ) );
					}
				}
			}
		}
	}
	set_kb_item( name: "netgear/prosafe/http/" + port + "/model", value: model );
	set_kb_item( name: "netgear/prosafe/http/" + port + "/fw_version", value: fw_version );
	set_kb_item( name: "netgear/prosafe/http/" + port + "/fw_build", value: fw_build );
	set_kb_item( name: "netgear/prosafe/http/detected", value: TRUE );
	set_kb_item( name: "netgear/prosafe/http/port", value: port );
	set_kb_item( name: "netgear/prosafe/detected", value: TRUE );
}
exit( 0 );

