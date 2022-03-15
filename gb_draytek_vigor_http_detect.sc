if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143661" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-03-31 08:28:25 +0000 (Tue, 31 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "DrayTek Vigor Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of DrayTek Vigor devices.

  This script performs HTTP based detection of DrayTek Vigor devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8080, 8081 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
fingerprint["bab52c2d280cc70bc4a1d3b7ac4bc4c8"] = "2120";
fingerprint["4172705528245ca522368b8a75a06ac1"] = "2760";
fingerprint["b05c6d98c3118430f9c3be10a22681fa"] = "2762";
fingerprint["75c151788f32d1f4a61400b2248453b0"] = "2860";
fingerprint["7e569db3f217067016a29aa245fd2332"] = "2862";
fingerprint["593a9bb0503491870ff4ed8ee39e490c"] = "2912";
fingerprint["f530aff4ad44eb41667d9638dfcf2041"] = "2925";
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/" );
res2 = http_get_cache( port: port, item: "/weblogin.htm" );
if(( ContainsString( res, "<title>Vigor " ) && ContainsString( res, "isomorphicDir" ) && IsMatchRegexp( res, "Server\\s*:\\s*DWS" ) ) || ( ContainsString( res2, "<title>Vigor Login Page</title>" ) && ContainsString( res2, "DrayTek" ) ) || IsMatchRegexp( res, "Server\\s*:\\s*DrayTek/Vigor" )){
	model = "unknown";
	version = "unknown";
	set_kb_item( name: "draytek/vigor/detected", value: TRUE );
	set_kb_item( name: "draytek/vigor/http/port", value: port );
	mod = eregmatch( pattern: "<title>Vigor ([0-9A-Z]+)", string: res );
	if(!isnull( mod[1] ) && !ContainsString( res, "Vigor Login Page" )){
		model = mod[1];
		set_kb_item( name: "draytek/vigor/http/" + port + "/concluded", value: mod[0] );
	}
	if(isnull( mod[1] )){
		mod = eregmatch( pattern: "Server\\s*:\\s*DrayTek/Vigor([0-9A-Z]+)", string: res );
		if(!isnull( mod[1] )){
			model = mod[1];
			set_kb_item( name: "draytek/vigor/http/" + port + "/concluded", value: mod[0] );
		}
	}
	if(isnull( mod[1] )){
		for url in make_list( "/images/login.png",
			 "/images/login1.png" ) {
			req = http_get( port: port, item: url );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			if(res){
				md5 = hexstr( MD5( res ) );
				fp = fingerprint[md5];
				if(fp){
					model = fp;
					set_kb_item( name: "draytek/vigor/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
					break;
				}
			}
		}
	}
	set_kb_item( name: "draytek/vigor/http/" + port + "/model", value: model );
	set_kb_item( name: "draytek/vigor/http/" + port + "/version", value: version );
}
exit( 0 );

