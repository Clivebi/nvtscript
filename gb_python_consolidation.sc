if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112857" );
	script_version( "2021-07-09T08:01:09+0000" );
	script_tag( name: "last_modification", value: "2021-07-09 08:01:09 +0000 (Fri, 09 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-02-01 08:12:11 +0000 (Mon, 01 Feb 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Python Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_dependencies( "gb_python_ssh_login_detect.sc", "gb_python_http_detect.sc", "gb_python_detect_macosx.sc", "gb_python_detect_win.sc" );
	script_mandatory_keys( "python/detected" );
	script_xref( name: "URL", value: "https://www.python.org/" );
	script_tag( name: "summary", value: "Consolidation of Python detections." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("cpe.inc.sc");
if(!get_kb_item( "python/detected" )){
	exit( 0 );
}
report = "";
for source in make_list( "ssh-login",
	 "smb-login",
	 "http" ) {
	install_list = get_kb_list( "python/" + source + "/*/installs" );
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
		conclurl = infos[4];
		cpe = build_cpe( value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:python:python:" );
		if(!cpe){
			cpe = "cpe:/a:python:python";
		}
		if(source == "http"){
			source = "www";
		}
		register_product( cpe: cpe, location: install, port: port, service: source );
		if(report){
			report += "\n\n";
		}
		report += build_detection_report( app: "Python", version: version, install: install, cpe: cpe, concludedUrl: conclurl, concluded: concl );
	}
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

