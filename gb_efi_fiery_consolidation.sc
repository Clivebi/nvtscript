if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146697" );
	script_version( "2021-09-13T12:24:15+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:24:15 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-10 14:18:44 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "EFI Fiery Detection Consolidation" );
	script_tag( name: "summary", value: "Consolidation of EFI Fiery detections." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_efi_fiery_http_detect.sc", "gb_efi_fiery_ftp_detect.sc", "gb_efi_fiery_snmp_detect.sc" );
	script_mandatory_keys( "efi/fiery/detected" );
	script_xref( name: "URL", value: "https://www.efi.com/products/fiery-servers-and-software/" );
	exit( 0 );
}
if(!get_kb_item( "efi/fiery/detected" )){
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
detected_version = "unknown";
location = "/";
for source in make_list( "http",
	 "ftp",
	 "snmp" ) {
	version_list = get_kb_list( "efi/fiery/" + source + "/*/version" );
	for version in version_list {
		if(version != "unknown" && detected_version == "unknown"){
			detected_version = version;
			break;
		}
	}
}
cpe = build_cpe( value: tolower( detected_version ), exp: "([0-9a-z._]+)", base: "cpe:/a:efi:fiery:" );
if(!cpe){
	cpe = "cpe:/a:efi:fiery";
}
if(http_ports = get_kb_list( "efi/fiery/http/port" )){
	for port in http_ports {
		extra += "HTTP(s) on port " + port + "/tcp\n";
		concluded = get_kb_item( "efi/fiery/http/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		concUrl = get_kb_item( "efi/fiery/http/" + port + "/concludedUrl" );
		if(concUrl){
			extra += "  Concluded from version/product identification location: " + concUrl + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "www" );
	}
}
if(ftp_ports = get_kb_list( "efi/fiery/ftp/port" )){
	for port in ftp_ports {
		extra += "FTP on port " + port + "/tcp\n";
		concluded = get_kb_item( "efi/fiery/ftp/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "ftp" );
	}
}
if(snmp_ports = get_kb_list( "efi/fiery/snmp/port" )){
	for port in snmp_ports {
		extra += "SNMP on port " + port + "/udp\n";
		concluded = get_kb_item( "efi/fiery/snmp/" + port + "/concluded" );
		if(concluded){
			extra += "  Concluded from version/product identification result: " + concluded + "\n";
		}
		register_product( cpe: cpe, location: location, port: port, service: "snmp", proto: "udp" );
	}
}
report = build_detection_report( app: "EFI Fiery", version: detected_version, install: location, cpe: cpe );
if(extra){
	report += "\n\nDetection methods:\n";
	report += "\n" + extra;
}
log_message( port: 0, data: report );
pref = get_kb_item( "global_settings/exclude_printers" );
if(pref == "yes"){
	log_message( port: 0, data: "The remote host is a printer. The scan has been disabled against this host.\n" + "If you want to scan the remote host, uncheck the \"Exclude printers from scan\" " + "option and re-scan it." );
	set_kb_item( name: "Host/dead", value: TRUE );
}
exit( 0 );

