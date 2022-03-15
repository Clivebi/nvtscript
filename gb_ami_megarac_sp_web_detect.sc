if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105383" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-09-23 10:26:45 +0200 (Wed, 23 Sep 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "MegaRAC SP Firmware Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of AMI MegaRAC SP Firmware" );
	script_tag( name: "insight", value: "The remote host is a MegaRAC remote management controller. MegaRAC Service
Processors come in various formats - PCI cards, embedded modules, software-only." );
	script_xref( name: "URL", value: "http://www.ami.com/products/remote-management/service-processor/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 443 );
buf = http_get_cache( item: "/index.html", port: port );
if(!ContainsString( buf, "<title>Megarac SP</title>" ) || !ContainsString( buf, "COPYRIGHT American Megatrends" )){
	buf = http_get_cache( item: "/#login", port: port );
	if(!ContainsString( buf, "<title>MegaRAC SP" ) || !ContainsString( buf, "class=\"processing_img_inner\"" )){
		exit( 0 );
	}
}
cpe = "cpe:/o:ami:megarac_sp";
set_kb_item( name: "ami_megarac_sp/installed", value: TRUE );
register_product( cpe: cpe, location: "/", port: port, service: "www" );
os_register_and_report( os: "MegaRAC SP", cpe: cpe, banner_type: "HTTP banner", port: port, desc: "MegaRAC SP Firmware Detection", runs_key: "unixoide" );
log_message( data: build_detection_report( app: "AMI MegaRAC SP Firmware", install: "/", cpe: cpe ), port: port );
exit( 0 );

