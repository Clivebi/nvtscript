if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117275" );
	script_version( "2021-10-06T05:47:37+0000" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2021-03-26 07:12:17 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Dnsmasq Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_dnsmasq_dns_detect.sc", "gb_dnsmasq_ssh_login_detect.sc" );
	script_mandatory_keys( "thekelleys/dnsmasq/detected" );
	script_tag( name: "summary", value: "Consolidation of Dnsmasq detections." );
	script_xref( name: "URL", value: "https://thekelleys.org.uk/dnsmasq/doc.html" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("cpe.inc.sc");
if(!get_kb_item( "thekelleys/dnsmasq/detected" )){
	exit( 0 );
}
report = "";
for source in make_list( "ssh-login",
	 "dns-tcp",
	 "dns-udp" ) {
	install_list = get_kb_list( "thekelleys/dnsmasq/" + source + "/*/installs" );
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
		proto = "";
		cpe = build_cpe( value: version, exp: "^([0-9.]+)((rc|test)[0-9]+)?", base: "cpe:/a:thekelleys:dnsmasq:" );
		if(!cpe){
			cpe = "cpe:/a:thekelleys:dnsmasq";
		}
		if( source == "dns-tcp" ){
			source = "domain";
			proto = "tcp";
		}
		else {
			if(source == "dns-udp"){
				source = "domain";
				proto = "udp";
			}
		}
		register_product( cpe: cpe, location: install, port: port, service: source, proto: proto );
		if(report){
			report += "\n\n";
		}
		report += build_detection_report( app: "Dnsmasq", version: version, install: install, cpe: cpe, concluded: concl );
	}
}
if(report){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", port: port, desc: "Dnsmasq Detection Consolidation", runs_key: "unixoide" );
	log_message( port: 0, data: report );
}
exit( 0 );

