if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113244" );
	script_version( "$Revision: 12413 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2018-08-07 10:33:33 +0200 (Tue, 07 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Autonomic Controls Detection (Consolidation)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_autonomic_controls_http_detect.sc", "gb_autonomic_controls_telnet_detect.sc" );
	script_mandatory_keys( "autonomic_controls/detected" );
	script_tag( name: "summary", value: "Reports on the detections for Autonomic Controls devices." );
	script_xref( name: "URL", value: "http://www.autonomic-controls.com/products/" );
	exit( 0 );
}
CPE = "cpe:/h:autonomic_controls:remote:";
require("host_details.inc.sc");
require("cpe.inc.sc");
concluded = "";
extra = "Concluded from: \r\n";
if(ver = get_kb_item( "autonomic_controls/http/version" )){
	version = ver;
	concluded = "HTTP";
	port = get_kb_item( "autonomic_controls/http/port" );
	concl = get_kb_item( "autonomic_controls/http/concluded" );
	extra += "\r\n  - HTTP( Port " + port + " ): " + concl;
}
if(ver = get_kb_item( "autonomic_controls/telnet/version" )){
	if(!version){
		version = ver;
	}
	if( concluded == "" ) {
		concluded = "Telnet";
	}
	else {
		concluded += " + Telnet";
	}
	port = get_kb_item( "autonomic_controls/telnet/port" );
	concl = get_kb_item( "autonomic_controls/telnet/concluded" );
	extra += "\r\n  - Telnet( Port " + port + " ): " + concl;
}
register_and_report_cpe( app: "Autonomic Controls", ver: version, concluded: concluded, base: CPE, expr: "([0-9.]+)", regPort: 0, extra: extra );
exit( 0 );

