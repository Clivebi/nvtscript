if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145462" );
	script_version( "2021-07-19T12:32:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-19 12:32:02 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-02-26 05:56:14 +0000 (Fri, 26 Feb 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "OpenSSL Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of OpenSSL detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_openssl_ssh_login_detect.sc", "gb_openssl_smb_login_detect.sc", "gb_openssl_http_detect.sc", "gb_openssl_ssh_detect.sc" );
	script_mandatory_keys( "openssl/detected" );
	script_xref( name: "URL", value: "https://www.openssl.org/" );
	exit( 0 );
}
if(!get_kb_item( "openssl/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
report = "";
for source in make_list( "http",
	 "ssh-login",
	 "smb-login",
	 "ssh" ) {
	install_list = get_kb_list( "openssl/" + source + "/*/installs" );
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
		extra = infos[4];
		conclurl = infos[5];
		cpe = build_cpe( value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:openssl:openssl:" );
		if(!cpe){
			cpe = "cpe:/a:openssl:openssl";
		}
		if(source == "http"){
			source = "www";
		}
		register_product( cpe: cpe, location: install, port: port, service: source );
		if(report){
			report += "\n\n";
		}
		report += build_detection_report( app: "OpenSSL", version: version, install: install, cpe: cpe, concluded: concl, concludedUrl: conclurl, extra: extra );
	}
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

