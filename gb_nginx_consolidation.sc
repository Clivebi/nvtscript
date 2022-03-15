if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113787" );
	script_version( "2021-02-16T15:25:33+0000" );
	script_tag( name: "last_modification", value: "2021-02-16 15:25:33 +0000 (Tue, 16 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-01-26 14:11:11 +0100 (Tue, 26 Jan 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "nginx Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_nginx_http_detect.sc", "gb_nginx_ssh_login_detect.sc" );
	script_mandatory_keys( "nginx/detected" );
	script_tag( name: "summary", value: "Consolidation of nginx detections." );
	script_xref( name: "URL", value: "https://www.nginx.com/" );
	exit( 0 );
}
if(!get_kb_item( "nginx/detected" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("cpe.inc.sc");
report = "";
for proto in make_list( "ssh-login",
	 "http" ) {
	install_list = get_kb_list( "nginx/" + proto + "/*/installs" );
	if(!install_list){
		continue;
	}
	install_list = sort( install_list );
	for install in install_list {
		infos = split( buffer: install, sep: "#---#", keep: FALSE );
		if(max_index( infos ) < 3){
			continue;
		}
		port = infos[0];
		install = infos[1];
		version = infos[2];
		concl = infos[3];
		concl_url = infos[4];
		extra = infos[5];
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:nginx:nginx:" );
		if(!cpe){
			cpe = "cpe:/a:nginx:nginx";
		}
		if( proto == "http" ) {
			service = "www";
		}
		else {
			service = proto;
		}
		register_product( cpe: cpe, location: install, port: port, service: service );
		if(report){
			report += "\n\n";
		}
		report += build_detection_report( app: "nginx", version: version, install: install, cpe: cpe, extra: extra, concludedUrl: concl_url, concluded: concl );
	}
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

