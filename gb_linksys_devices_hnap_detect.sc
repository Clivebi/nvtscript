if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144525" );
	script_version( "2020-10-06T06:39:05+0000" );
	script_tag( name: "last_modification", value: "2020-10-06 06:39:05 +0000 (Tue, 06 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-03 06:02:37 +0000 (Thu, 03 Sep 2020)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Linksys Device Detection (HNAP)" );
	script_tag( name: "summary", value: "HNAP based detection of Linksys devices." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_dependencies( "gb_hnap_detect.sc" );
	script_mandatory_keys( "HNAP/port" );
	exit( 0 );
}
if(!port = get_kb_item( "HNAP/port" )){
	exit( 0 );
}
vendor = get_kb_item( "HNAP/" + port + "/vendor" );
if(!vendor || !ContainsString( tolower( vendor ), "linksys" )){
	exit( 0 );
}
model = "unknown";
version = "unknown";
set_kb_item( name: "linksys/detected", value: TRUE );
set_kb_item( name: "linksys/hnap/port", value: port );
mod = get_kb_item( "HNAP/" + port + "/model" );
if(mod){
	model = mod;
	concl = get_kb_item( "HNAP/" + port + "/model_concluded" );
	if(concl){
		concluded = "\n    Model:        " + concl;
	}
}
vers = get_kb_item( "HNAP/" + port + "/firmware" );
if(vers){
	vers = eregmatch( pattern: "^([0-9.]+)", string: vers );
	if(!isnull( vers[1] )){
		version = vers[1];
		concl = get_kb_item( "HNAP/" + port + "/firmware_concluded" );
		if(concl){
			concluded += "\n    Version:      " + concl;
		}
	}
}
url = get_kb_item( "HNAP/" + port + "/conclurl" );
if(url){
	set_kb_item( name: "linksys/hnap/" + port + "/concludedUrl", value: url );
}
set_kb_item( name: "linksys/hnap/" + port + "/model", value: model );
set_kb_item( name: "linksys/hnap/" + port + "/version", value: version );
if(concluded){
	set_kb_item( name: "linksys/hnap/" + port + "/concluded", value: concluded );
}
exit( 0 );

