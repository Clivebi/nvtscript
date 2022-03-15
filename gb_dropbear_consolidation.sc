if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112869" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-02-26 10:57:11 +0000 (Fri, 26 Feb 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Dropbear Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_dependencies( "gb_dropbear_ssh_login_detect.sc", "gb_dropbear_ssh_detect.sc" );
	script_mandatory_keys( "dropbear_ssh/detected" );
	script_xref( name: "URL", value: "https://matt.ucc.asn.au/dropbear/dropbear.html" );
	script_tag( name: "summary", value: "Consolidation of Dropbear detections." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("cpe.inc.sc");
if(!get_kb_item( "dropbear_ssh/detected" )){
	exit( 0 );
}
report = "";
for source in make_list( "ssh-login",
	 "ssh" ) {
	install_list = get_kb_list( "dropbear_ssh/" + source + "/*/installs" );
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
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:dropbear_ssh_project:dropbear_ssh:" );
		if(!cpe){
			cpe = "cpe:/a:dropbear_ssh_project:dropbear_ssh";
		}
		register_product( cpe: cpe, location: install, port: port, service: source );
		os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", port: port, desc: "Dropbear Detection Consolidation", runs_key: "unixoide" );
		if(report){
			report += "\n\n";
		}
		report += build_detection_report( app: "Dropbear SSH", version: version, install: install, cpe: cpe, concluded: concl );
	}
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

