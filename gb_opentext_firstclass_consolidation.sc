if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113610" );
	script_version( "2020-02-04T07:36:22+0000" );
	script_tag( name: "last_modification", value: "2020-02-04 07:36:22 +0000 (Tue, 04 Feb 2020)" );
	script_tag( name: "creation_date", value: "2019-12-02 13:55:55 +0200 (Mon, 02 Dec 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "OpenText FirstClass Detection (Consolidation" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_opentext_firstclass_http_detect.sc", "gb_opentext_firstclass_imap_detect.sc", "gb_opentext_firstclass_smtp_detect.sc", "gb_opentext_firstclass_ftp_detect.sc" );
	script_mandatory_keys( "opentext/firstclass/detected" );
	script_tag( name: "summary", value: "Checks whether OpenText FirstClass is present on
  the target system and if so, tries to figure out the installed version." );
	script_xref( name: "URL", value: "https://www.opentext.com/products-and-solutions/products/specialty-technologies/firstclass" );
	exit( 0 );
}
CPE = "cpe:/a:opentext:opentext_firstclass:";
require("host_details.inc.sc");
version = "unknown";
extra = "Concluded from:";
concluded = "";
for proto in make_list( "imap",
	 "http",
	 "smtp",
	 "ftp" ) {
	if( get_kb_item( "opentext/firstclass/" + proto + "/detected" ) ){
		extra += "\n\n" + toupper( proto );
		if(concluded != ""){
			concluded += ", ";
		}
		concluded += toupper( proto );
	}
	else {
		continue;
	}
	if(ver = get_kb_item( "opentext/firstclass/" + proto + "/version" )){
		if(version == "unknown"){
			version = ver;
			CPE += version;
		}
		if(concl = get_kb_item( "opentext/firstclass/" + proto + "/concluded" )){
			extra += ":\n" + concl;
		}
		if(port = get_kb_item( "opentext/firstclass/" + proto + "/port" )){
			register_product( cpe: CPE, location: port + "/tcp", port: port, service: proto );
		}
	}
}
log_message( port: 0, data: build_detection_report( app: "OpenText FirstClass", version: version, cpe: CPE, concluded: concluded, extra: extra ) );
exit( 0 );

