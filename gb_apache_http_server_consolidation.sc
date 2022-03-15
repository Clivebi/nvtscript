if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117232" );
	script_version( "2021-02-25T13:36:35+0000" );
	script_tag( name: "last_modification", value: "2021-02-25 13:36:35 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-25 11:11:24 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Apache HTTP Server Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_apache_http_server_ssh_login_detect.sc", "secpod_apache_http_server_http_detect.sc" );
	script_mandatory_keys( "apache/http_server/detected" );
	script_tag( name: "summary", value: "Consolidation of Apache HTTP Server detections." );
	script_xref( name: "URL", value: "https://httpd.apache.org" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!get_kb_item( "apache/http_server/detected" )){
	exit( 0 );
}
report = "";
for source in make_list( "ssh-login",
	 "http" ) {
	install_list = get_kb_list( "apache/http_server/" + source + "/*/installs" );
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
		cpe = "cpe:/a:apache:http_server";
		if(version && version != "unknown"){
			cpe += ":" + str_replace( string: version, find: "-", replace: ":" );
		}
		if(source == "http"){
			source = "www";
		}
		register_product( cpe: cpe, location: install, port: port, service: source );
		if(report){
			report += "\n\n";
		}
		report += build_detection_report( app: "Apache HTTP Server", version: version, install: install, cpe: cpe, concludedUrl: concl_url, concluded: concl );
	}
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

