if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141670" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-11-12 15:24:08 +0700 (Mon, 12 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Veritas NetBackup Appliance Detection" );
	script_tag( name: "summary", value: "Detection of Veritas NetBackup Appliance.

The script sends a connection request to the server and attempts to detect Veritas NetBackup Appliance and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.veritas.com/product/backup-and-recovery/netbackup-appliances" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/appliance/" );
if(ContainsString( res, "Veritas NetBackup Web Management Console" ) && ContainsString( res, "SubmitLogin.action" )){
	version = "unknown";
	vers = eregmatch( pattern: "<span>Version ([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "veritas_netbackup_appliance/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:veritas:netbackup_appliance:" );
	if(!cpe){
		cpe = "cpe:/a:veritas:netbackup_appliance";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Veritas NetBackup NetBackup Appliance", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

