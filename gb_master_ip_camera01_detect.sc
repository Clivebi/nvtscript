if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812657" );
	script_version( "2020-02-03T13:52:45+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-02-03 13:52:45 +0000 (Mon, 03 Feb 2020)" );
	script_tag( name: "creation_date", value: "2018-01-22 12:19:43 +0530 (Mon, 22 Jan 2018)" );
	script_name( "Master IP Camera Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_thttpd_detect.sc" );
	script_mandatory_keys( "thttpd/detected" );
	script_tag( name: "summary", value: "This script tries to detect a Master IP Camera
  and its version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
thttpd_CPE = "cpe:/a:acme:thttpd";
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: thttpd_CPE )){
	exit( 0 );
}
res = http_get_cache( item: "/web/index.html", port: port );
if(( ContainsString( res, "<title>ipCAM<" ) || ContainsString( res, "<title>Camera<" ) ) && ContainsString( res, "cgi-bin/hi3510" ) && ContainsString( res, ">OCX" )){
	version = "unknown";
	set_kb_item( name: "MasterIP/Camera/Detected", value: TRUE );
	cpe = "cpe:/h:masterip:masterip_camera";
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Master IP Camera", version: version, install: "/", cpe: cpe ), port: port );
}
exit( 0 );

