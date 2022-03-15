if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113225" );
	script_version( "$Revision: 12413 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2018-07-06 10:41:45 +0200 (Fri, 06 Jul 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Ecessa ShieldLink Detection (Consolidation)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_ecessa_shieldlink_snmp_detect.sc", "gb_ecessa_shieldlink_telnet_detect.sc" );
	script_mandatory_keys( "ecessa_link/detected" );
	script_tag( name: "summary", value: "Reports findings of Ecessa ShieldLink
  SNMP and Telnet detections." );
	script_xref( name: "URL", value: "https://www.ecessa.com/powerlink/" );
	script_xref( name: "URL", value: "https://www.ecessa.com/powerlink/product_comp_shieldlink/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("cpe.inc.sc");
if( get_kb_item( "ecessa_shieldlink/detected" ) ){
	kb_base = "ecessa_shieldlink";
	CPE = "cpe:/h:ecessa:shieldlink:";
	app_name = "Ecessa ShieldLink";
}
else {
	if( get_kb_item( "ecessa_powerlink/detected" ) ){
		kb_base = "ecessa_powerlink";
		CPE = "cpe:/h:ecessa:powerlink";
		app_name = "Ecessa PowerLink";
	}
	else {
		exit( 0 );
	}
}
version = "unknown";
extra = "Detection methods:\r\n";
concluded = "";
for proto in make_list( "snmp",
	 "telnet" ) {
	if(version == "unknown"){
		vers = get_kb_item( kb_base + "/" + proto + "/version" );
		if(!isnull( vers ) && vers != "unknown"){
			version = vers;
		}
	}
	port = get_kb_item( kb_base + "/" + proto + "/port" );
	if(!isnull( port )){
		extra += "\r\n" + toupper( proto ) + " at port: " + port;
	}
	proto_concluded = get_kb_item( kb_base + "/" + proto + "/concluded" );
	if(!isnull( proto_concluded )){
		concluded += "\r\n" + toupper( proto ) + " concluded from:\r\n" + proto_concluded;
	}
}
register_and_report_cpe( app: app_name, ver: version, concluded: concluded, base: CPE, expr: "([0-9.]+)", regPort: 0, extra: extra );
exit( 0 );

