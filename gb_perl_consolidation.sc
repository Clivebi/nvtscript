if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117562" );
	script_version( "2021-07-14T14:10:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-14 14:10:02 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-14 13:03:29 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Perl Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_dependencies( "gb_perl_http_detect.sc", "gb_perl_ssh_login_detect.sc" );
	script_mandatory_keys( "perl/detected" );
	script_xref( name: "URL", value: "https://www.perl.org/" );
	script_tag( name: "summary", value: "Consolidation of Perl detections." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("cpe.inc.sc");
if(!get_kb_item( "perl/detected" )){
	exit( 0 );
}
report = "";
for source in make_list( "ssh-login",
	 "http" ) {
	install_list = get_kb_list( "perl/" + source + "/*/installs" );
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
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:perl:perl:" );
		if(!cpe){
			cpe = "cpe:/a:perl:perl";
		}
		if(source == "http"){
			source = "www";
		}
		register_product( cpe: cpe, location: install, port: port, service: source );
		if(report){
			report += "\n\n";
		}
		report += build_detection_report( app: "Perl", version: version, install: install, cpe: cpe, concludedUrl: conclurl, concluded: concl );
	}
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

