if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142000" );
	script_version( "$Revision: 13720 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-18 08:43:24 +0100 (Mon, 18 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2019-02-15 09:14:08 +0700 (Fri, 15 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Snom Detection Consolidation" );
	script_tag( name: "summary", value: "The script reports a detected Snom device including the version number." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_snom_detect.sc", "gb_snom_http_detect.sc" );
	script_mandatory_keys( "snom/detected" );
	script_xref( name: "URL", value: "https://www.snom.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
if(!get_kb_item( "snom/detected" )){
	exit( 0 );
}
detected_version = "unknown";
detected_model = "";
for source in make_list( "sip",
	 "http" ) {
	version_list = get_kb_list( "snom/" + source + "/*/version" );
	for vers in version_list {
		if(vers != "unknown" && detected_version == "unknown"){
			detected_version = vers;
		}
	}
	model_list = get_kb_list( "snom/" + source + "/*/model" );
	for mod in model_list {
		if(mod != "unknown" && detected_model == ""){
			detected_model = mod;
		}
	}
}
if( detected_model != "" ){
	cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/h:snom:snom_" + detected_model + ":" );
	if(!cpe){
		cpe = "cpe:/h:snom:snom_" + detected_model;
	}
}
else {
	cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/h:snom:snom_unknown_model:" );
	if(!cpe){
		cpe = "cpe:/h:snom:snom_unknown_model";
	}
}
if(http_ports = get_kb_list( "snom/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		register_product( cpe: cpe, location: "/", port: port, service: "www" );
	}
}
if(sip_ports = get_kb_list( "snom/sip/port" )){
	for port in sip_ports {
		proto = get_kb_item( "snom/sip/" + port + "/proto" );
		concl = get_kb_item( "snom/sip/" + port + "/" + proto + "/concluded" );
		extra += "SIP on port " + port + "/" + proto + "\nBanner: " + concl + "\n";
		register_product( cpe: cpe, location: port + "/" + proto, port: port, service: "sip" );
	}
}
report = build_detection_report( app: "Snom " + detected_model, version: detected_version, install: "/", cpe: cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

