if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146148" );
	script_version( "2021-06-18T07:32:53+0000" );
	script_tag( name: "last_modification", value: "2021-06-18 07:32:53 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-18 03:38:00 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "OpenLDAP Detection (Consolidation)" );
	script_tag( name: "summary", value: "Consolidation of OpenLDAP detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_openldap_ssh_login_detect.sc" );
	script_mandatory_keys( "openldap/detected" );
	script_xref( name: "URL", value: "https://www.openldap.org/" );
	exit( 0 );
}
if(!get_kb_item( "openldap/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
report = "";
for source in make_list( "ssh-login" ) {
	install_list = get_kb_list( "openldap/" + source + "/*/installs" );
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
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:openldap:openldap:" );
		if(!cpe){
			cpe = "cpe:/a:openldap:openldap";
		}
		register_product( cpe: cpe, location: install, port: port, service: source );
		if(report){
			report += "\n\n";
		}
		report += build_detection_report( app: "OpenLDAP", version: version, install: install, cpe: cpe, concluded: concl );
	}
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

