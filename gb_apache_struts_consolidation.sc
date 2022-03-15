if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117280" );
	script_version( "2021-04-01T11:05:36+0000" );
	script_tag( name: "last_modification", value: "2021-04-01 11:05:36 +0000 (Thu, 01 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-03-30 07:49:07 +0000 (Tue, 30 Mar 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Apache Struts Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_apache_struts_ssh_login_detect.sc", "gb_apache_struts_http_detect.sc" );
	script_mandatory_keys( "apache/struts/detected" );
	script_tag( name: "summary", value: "Consolidation of Apache Struts detections." );
	script_xref( name: "URL", value: "https://struts.apache.org" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("cpe.inc.sc");
if(!get_kb_item( "apache/struts/detected" )){
	exit( 0 );
}
report = "";
for source in make_list( "ssh-login",
	 "http" ) {
	install_list = get_kb_list( "apache/struts/" + source + "/*/installs" );
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
		type = infos[4];
		app = "Apache Struts";
		if(type){
			app += type;
		}
		concl_url = infos[5];
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:struts:" );
		if(!cpe){
			cpe = "cpe:/a:apache:struts";
		}
		if(source == "http"){
			source = "www";
		}
		register_product( cpe: cpe, location: install, port: port, service: source );
		if(report){
			report += "\n\n";
		}
		report += build_detection_report( app: app, version: version, install: install, cpe: cpe, concludedUrl: concl_url, concluded: concl );
	}
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

