if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113291" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-11-08 14:45:45 +0100 (Thu, 08 Nov 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IPConfigure Orchid VMS Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects whether or not Orchid VMS is running on the
  target system, and if so, tries to detect the installed version." );
	script_xref( name: "URL", value: "https://www.ipconfigure.com/products/orchid" );
	script_xref( name: "URL", value: "https://www.ipconfigure.com/products/fusion" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
for location in nasl_make_list_unique( "/", http_cgi_dirs( port: 80 ) ) {
	dir = location;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/#/sign-in";
	buf = http_get_cache( item: url, port: port );
	built_loc = eregmatch( string: buf, pattern: "js[/]built[^.]*[.]js", icase: TRUE );
	if(isnull( built_loc[0] )){
		continue;
	}
	built_url = dir + "/" + built_loc[0];
	buf = http_get_cache( item: built_url, port: port );
	mod = eregmatch( string: buf, pattern: "APP_NAME:\"Orchid (Core|Fusion) VMS", icase: TRUE );
	if(isnull( mod[1] )){
		mod = eregmatch( string: buf, pattern: "\"[/](fusion|core)[/]orchids\"", icase: TRUE );
		if(isnull( mod[1] )){
			continue;
		}
	}
	type = tolower( mod[1] );
	replace_kb_item( name: "ipconfigure/orchid_vms/detected", value: TRUE );
	set_kb_item( name: "ipconfigure/orchid_vms/port", value: port );
	set_kb_item( name: "ipconfigure/orchid_vms/location", value: location );
	set_kb_item( name: "ipconfigure/orchid_vms/type", value: type );
	CPE = "cpe:/a:ipconfigure:orchid_" + type + "_vms:";
	version = "unknown";
	concluded = mod[0];
	ver_url = dir + "/service/version";
	buf = http_get_cache( item: ver_url, port: port );
	ver = eregmatch( string: buf, pattern: "\"version\"[ ]*:[ ]*\"([0-9.]+)\"", icase: TRUE );
	if(!isnull( ver[1] )){
		version = ver[1];
		set_kb_item( name: "ipconfigure/orchid_vms/version", value: version );
		concluded += "\n\n" + ver[0];
	}
	register_and_report_cpe( app: "Orchid " + type + " VMS", ver: version, concluded: concluded, base: CPE, expr: "([0-9.]+)", insloc: location, regPort: port, conclUrl: built_url );
	exit( 0 );
}
exit( 0 );

