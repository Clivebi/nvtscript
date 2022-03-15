if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146407" );
	script_version( "2021-07-30T10:14:55+0000" );
	script_tag( name: "last_modification", value: "2021-07-30 10:14:55 +0000 (Fri, 30 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-30 09:05:11 +0000 (Fri, 30 Jul 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Epson Printer Detection (PJL)" );
	script_tag( name: "summary", value: "Printer Job Language (PJL) based detection of Epson printer devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_pcl_pjl_detect.sc" );
	script_require_ports( "Services/hp-pjl", 9100 );
	script_mandatory_keys( "hp-pjl/banner/available" );
	exit( 0 );
}
port = get_kb_item( "hp-pjl/port" );
banner = get_kb_item( "hp-pjl/" + port + "/banner" );
if(!banner || !IsMatchRegexp( banner, "^EPSON " )){
	exit( 0 );
}
set_kb_item( name: "epson/printer/detected", value: TRUE );
set_kb_item( name: "epson/printer/hp-pjl/detected", value: TRUE );
set_kb_item( name: "epson/printer/hp-pjl/port", value: port );
set_kb_item( name: "epson/printer/hp-pjl/" + port + "/concluded", value: banner );
mod = eregmatch( pattern: "^EPSON ([^ ]+)", string: banner );
if(!isnull( mod[1] )){
	set_kb_item( name: "epson/printer/hp-pjl/" + port + "/model", value: mod[1] );
}
exit( 0 );

