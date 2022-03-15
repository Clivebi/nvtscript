if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108630" );
	script_version( "2021-09-13T06:24:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 06:24:59 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-08-29 10:01:52 +0000 (Thu, 29 Aug 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "RICOH Printer Detection (PJL)" );
	script_tag( name: "summary", value: "Printer Job Language (PJL) based detection of RICOH printer devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_pcl_pjl_detect.sc" );
	script_require_ports( "Services/hp-pjl", 9100 );
	script_mandatory_keys( "hp-pjl/banner/available" );
	exit( 0 );
}
port = get_kb_item( "hp-pjl/port" );
banner = get_kb_item( "hp-pjl/" + port + "/banner" );
if(!banner || !IsMatchRegexp( banner, "^RICOH " )){
	exit( 0 );
}
model = "unknown";
version = "unknown";
set_kb_item( name: "ricoh/printer/detected", value: TRUE );
set_kb_item( name: "ricoh/printer/hp-pjl/detected", value: TRUE );
set_kb_item( name: "ricoh/printer/hp-pjl/port", value: port );
set_kb_item( name: "ricoh/printer/hp-pjl/" + port + "/concluded", value: banner );
mod = eregmatch( pattern: "^RICOH ((Aficio )?[^ ]+ [^ ]*)", string: banner );
if(!isnull( mod[1] )){
	model = mod[1];
}
set_kb_item( name: "ricoh/printer/hp-pjl/" + port + "/model", value: model );
set_kb_item( name: "ricoh/printer/hp-pjl/" + port + "/fw_version", value: version );
exit( 0 );

