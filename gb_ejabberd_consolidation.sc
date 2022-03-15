if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144098" );
	script_version( "2020-06-09T09:51:17+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 09:51:17 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-06-09 09:18:01 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ejabberd Consolidation" );
	script_tag( name: "summary", value: "Reports the ejabberd version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_ejabberd_xmpp_detect.sc", "gb_ejabberd_http_detect.sc", "gb_ejabberd_sip_detect.sc" );
	script_mandatory_keys( "ejabberd/detected" );
	exit( 0 );
}
if(!get_kb_item( "ejabberd/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
detected_version = "unknown";
location = "/";
for source in make_list( "sip",
	 "http",
	 "xmpp" ) {
	version_list = get_kb_list( "ejabberd/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
}
if(detected_version != "unknown"){
	cpe = build_cpe( value: detected_version, exp: "^([0-9a-z+~.-]+)", base: "cpe:/a:process-one:ejabberd:" );
}
if(!cpe){
	cpe = "cpe:/a:process-one:ejabberd";
}
if(http_ports = get_kb_list( "ejabberd/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "ejabberd/http/" + port + "/concluded" );
		concUrl = get_kb_item( "ejabberd/http/" + port + "/concludedUrl" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
			extra += "  Concluded from version/product identification location: " + concUrl + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(xmpp_ports = get_kb_list( "ejabberd/xmpp/port" )){
	for port in xmpp_ports {
		extra += "XMPP on port " + port + "/tcp\n";
		concluded = get_kb_item( "ejabberd/xmpp/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: "/", port: port, service: "xmpp" );
	}
}
if(sip_ports = get_kb_list( "ejabberd/sip/port" )){
	for port in sip_ports {
		proto = get_kb_item( "ejabberd/sip/" + port + "/proto" );
		extra += "SIP on port " + port + "/" + proto + "\n";
		concluded = get_kb_item( "ejabberd/sip/" + port + "/concluded" );
		extra += "  SIP banner: " + concluded + "\n";
		register_product( cpe: cpe, location: location, port: port, service: "sip", proto: proto );
	}
}
report = build_detection_report( app: "ejabberd", version: detected_version, install: location, cpe: cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
exit( 0 );

