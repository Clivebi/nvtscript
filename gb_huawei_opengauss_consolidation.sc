if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108974" );
	script_version( "2020-10-27T08:26:53+0000" );
	script_tag( name: "last_modification", value: "2020-10-27 08:26:53 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-10-26 07:21:21 +0000 (Mon, 26 Oct 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Huawei openGauss Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "gb_huawei_opengauss_ssh_login_detect.sc" );
	script_mandatory_keys( "huawei/opengauss/detected" );
	script_xref( name: "URL", value: "https://opengauss.org" );
	script_tag( name: "summary", value: "Consolidation of Huawei openGauss detections." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("cpe.inc.sc");
if(!get_kb_item( "huawei/opengauss/detected" )){
	exit( 0 );
}
report = "";
for source in make_list( "ssh-login" ) {
	install_list = get_kb_list( "huawei/opengauss/" + source + "/*/installs" );
	if(!install_list){
		continue;
	}
	install_list = sort( install_list );
	for install in install_list {
		infos = split( buffer: install, sep: "#---#", keep: FALSE );
		port = infos[0];
		install = infos[1];
		concl = infos[2];
		version = infos[3];
		build = infos[4];
		extra = "";
		cpe = build_cpe( value: tolower( version ), exp: "^([vrchps0-9.]+)", base: "cpe:/a:huawei:opengauss:" );
		if(!cpe){
			cpe = "cpe:/a:huawei:opengauss";
		}
		register_product( cpe: cpe, location: install, port: port, service: source );
		if(build != "unknown" && strlen( build ) == 8){
			extra += "Internal build: " + build;
		}
		if(report){
			report += "\n\n";
		}
		report += build_detection_report( app: "Huawei openGauss", version: version, install: install, cpe: cpe, concluded: concl, extra: extra );
	}
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

