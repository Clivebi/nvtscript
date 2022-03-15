if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140330" );
	script_version( "2021-07-12T11:29:43+0000" );
	script_tag( name: "last_modification", value: "2021-07-12 11:29:43 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2017-08-28 15:51:57 +0700 (Mon, 28 Aug 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "IceWarp Mail Server Detection (Consolidation)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_icewarp_http_detect.sc", "gb_icewarp_pop3_detect.sc", "gb_icewarp_smtp_detect.sc", "gb_icewarp_imap_detect.sc" );
	script_mandatory_keys( "icewarp/mailserver/detected" );
	script_xref( name: "URL", value: "http://www.icewarp.com/" );
	script_tag( name: "summary", value: "Consolidation of detections of IceWarp Mail Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
if(!get_kb_item( "icewarp/mailserver/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:icewarp:mail_server";
version = "unknown";
for proto in make_list( "http",
	 "pop3",
	 "smtp",
	 "imap" ) {
	for port in get_kb_list( "icewarp/mailserver/" + proto + "/port" ) {
		if(!vers = get_kb_item( "icewarp/mailserver/" + proto + "/" + port + "/version" )){
			continue;
		}
		if(version == "unknown" && vers != "unknown"){
			version = vers;
		}
		concl = get_kb_item( "icewarp/mailserver/" + proto + "/" + port + "/concluded" );
		if(concl){
			concluded += "\n - on port " + port + "/tcp:";
			concluded += "\n" + concl;
			if(proto == "http"){
				conclUrl = get_kb_item( "icewarp/mailserver/" + proto + "/" + port + "/concludedUrl" );
				if(conclUrl){
					concluded += "\n  - Identification location(s):\n" + conclUrl;
				}
			}
		}
		install = port + "/tcp";
		service = proto;
		if(service == "http"){
			service = "www";
			install = "/webmail";
		}
		if(!cpe = build_cpe( value: vers, exp: "([0-9.]+)", base: CPE + ":" )){
			cpe = CPE;
		}
		register_product( cpe: cpe, location: install, port: port, service: service );
	}
}
if(!cpe = build_cpe( value: version, exp: "([0-9.]+)", base: CPE + ":" )){
	cpe = CPE;
}
report = build_detection_report( app: "IceWarp Mail Server", version: version, install: "/", cpe: cpe, concluded: concluded );
log_message( data: report, port: 0 );
exit( 0 );

