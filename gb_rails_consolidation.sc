if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113711" );
	script_version( "2020-11-30T08:49:07+0000" );
	script_tag( name: "last_modification", value: "2020-11-30 08:49:07 +0000 (Mon, 30 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-07-06 10:25:00 +0200 (Mon, 06 Jul 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Ruby on Rails Detection (Consolidation)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_ruby_rails_detect.sc", "secpod_ruby_rails_detect.sc" );
	script_mandatory_keys( "rails/detected" );
	script_tag( name: "summary", value: "Consolidates and reports the detected Ruby on Rails installation(s)." );
	script_xref( name: "URL", value: "https://rubyonrails.org/" );
	exit( 0 );
}
if(!get_kb_item( "rails/detected" )){
	exit( 0 );
}
CPE_base = "cpe:/a:rubyonrails:rails";
require("host_details.inc.sc");
require("cpe.inc.sc");
report = "";
for proto in make_list( "ssh-login",
	 "http" ) {
	install_list = get_kb_list( "rails/" + proto + "/*/install" );
	if(!install_list){
		continue;
	}
	for install in install_list {
		infos = split( buffer: install, sep: "#---#", keep: FALSE );
		if(max_index( infos ) < 3){
			continue;
		}
		port = infos[0];
		location = infos[1];
		version = infos[2];
		concluded = infos[3];
		conclLocation = infos[4];
		if(!cpe = build_cpe( value: version, exp: "([0-9.]+)", base: CPE_base + ":" )){
			cpe = CPE_base;
		}
		report_proto = proto;
		if(proto == "http"){
			report_proto = "www";
		}
		register_product( cpe: cpe, location: location, port: port, service: report_proto );
		if( proto == "http" ) {
			extra = "\nDetected via HTTP";
		}
		else {
			if(proto == "ssh-login"){
				extra = "\nDetected via SSH login";
			}
		}
		extra += " on port " + port + "/tcp";
		if(report){
			report += "\n\n";
		}
		report += build_detection_report( app: "Ruby on Rails", version: version, install: location, cpe: cpe, concluded: concluded, concludedUrl: conclLocation, extra: extra );
	}
}
if(report){
	log_message( data: report, port: 0 );
}
exit( 0 );

