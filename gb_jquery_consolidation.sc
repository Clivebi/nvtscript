if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150658" );
	script_version( "2021-09-21T07:58:23+0000" );
	script_tag( name: "last_modification", value: "2021-09-21 07:58:23 +0000 (Tue, 21 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-06-03 14:04:05 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "jQuery Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_dependencies( "gb_jquery_http_detect.sc", "gb_jquery_ssh_login_detect.sc" );
	script_mandatory_keys( "jquery/detected" );
	script_xref( name: "URL", value: "https://jquery.com/" );
	script_tag( name: "summary", value: "Consolidation of jQuery detections." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("cpe.inc.sc");
if(!get_kb_item( "jquery/detected" )){
	exit( 0 );
}
report = "";
for proto in make_list( "ssh-login",
	 "http" ) {
	install_list = get_kb_list( "jquery/" + proto + "/*/installs" );
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
		cpe = build_cpe( value: version, exp: "^([0-9.]+)-?(rc[0-9])?", base: "cpe:/a:jquery:jquery:" );
		if(!cpe){
			cpe = "cpe:/a:jquery:jquery";
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
		report += build_detection_report( app: "jQuery", version: version, install: install, cpe: cpe, extra: extra, concludedUrl: concl_url, concluded: concl );
	}
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

