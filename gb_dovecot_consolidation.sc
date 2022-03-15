if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113212" );
	script_version( "$Revision: 13403 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-01 11:33:22 +0100 (Fri, 01 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2018-06-26 11:11:11 +0200 (Tue, 26 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Dovecot Detection (Consolidation)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "sw_dovecot_detect.sc", "secpod_dovecot_detect.sc" );
	script_mandatory_keys( "dovecot/detected" );
	script_tag( name: "summary", value: "Reports Dovecot installation including version and location." );
	script_xref( name: "URL", value: "https://www.dovecot.org/" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!get_kb_item( "dovecot/detected" )){
	exit( 0 );
}
base_cpe = "cpe:/a:dovecot:dovecot";
report = "";
info_list = get_kb_list( "dovecot/detection-info" );
if(!info_list){
	exit( 0 );
}
info_list = sort( info_list );
for info in info_list {
	_info_list = split( buffer: info, sep: "#--#", keep: FALSE );
	if(max_index( _info_list ) != 6){
		continue;
	}
	name = _info_list[0];
	service = _info_list[1];
	port = _info_list[2];
	location = _info_list[3];
	version = _info_list[4];
	concluded = _info_list[5];
	if( version != "unknown" ) {
		cpe = base_cpe + ":" + version;
	}
	else {
		cpe = base_cpe;
	}
	register_product( cpe: cpe, location: location, port: port, service: service );
	if(report){
		report += "\n\n";
	}
	report += build_detection_report( app: "Dovecot", version: version, install: location, cpe: cpe, concluded: concluded );
	report += "\n\nDetection Method: " + name;
}
if(report){
	log_message( port: 0, data: report );
}
exit( 0 );

