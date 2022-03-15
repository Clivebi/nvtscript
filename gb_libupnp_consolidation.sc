if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113700" );
	script_version( "2021-03-19T10:51:02+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 10:51:02 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-06-08 13:57:00 +0200 (Mon, 08 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "libupnp Detection Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_libupnp_http_detect.sc", "gb_libupnp_upnp_detect.sc" );
	script_mandatory_keys( "libupnp/detected" );
	script_tag( name: "summary", value: "Consolidation of libupnp detecions." );
	script_xref( name: "URL", value: "https://pupnp.sourceforge.io/" );
	exit( 0 );
}
CPE_base = "cpe:/a:libupnp_project:libupnp";
require("host_details.inc.sc");
require("cpe.inc.sc");
something_to_report = FALSE;
version = "unknown";
concluded = "";
for proto in make_list( "upnp",
	 "http" ) {
	if(ports = get_kb_list( "libupnp/" + proto + "/port" )){
		something_to_report = TRUE;
		for port in ports {
			proto_version = get_kb_item( "libupnp/" + proto + "/" + port + "/version" );
			if(version == "unknown" && proto_version != "unknown" && proto_version != ""){
				version = proto_version;
			}
			concl = get_kb_item( "libupnp/" + proto + "/" + port + "/concluded" );
			if(!cpe = build_cpe( value: proto_version, exp: "([0-9.]+)", base: CPE_base + ":" )){
				cpe = CPE_base;
			}
			if(proto == "http"){
				tproto = "tcp";
				proto = "www";
			}
			if(proto == "upnp"){
				tproto = "udp";
			}
			register_product( cpe: cpe, location: port + "/" + tproto, port: port, proto: tproto, service: proto );
			if(concluded){
				concluded += "\n";
			}
			concluded += "\n" + port + "/" + tproto + ":\n" + concl;
		}
	}
}
if(something_to_report){
	if(!CPE = build_cpe( value: version, exp: "([0-9.]+)", base: CPE_base + ":" )){
		CPE = CPE_base;
	}
	report = build_detection_report( app: "libupnp", version: version, install: "/", cpe: CPE, concluded: concluded );
	log_message( data: report, port: 0 );
}
exit( 0 );

