if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113267" );
	script_version( "2021-05-04T09:23:47+0000" );
	script_tag( name: "last_modification", value: "2021-05-04 09:23:47 +0000 (Tue, 04 May 2021)" );
	script_tag( name: "creation_date", value: "2018-09-13 13:37:00 +0200 (Thu, 13 Sep 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "SAP NetWeaver AS Java Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of SAP NetWeaver Application Server (AS)
  Java." );
	script_xref( name: "URL", value: "https://wiki.scn.sap.com/wiki/display/ASJAVA/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
for location in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	dir = location;
	if(dir == "/"){
		dir = "";
	}
	url1 = dir + "/startPage";
	buf1 = http_get_cache( item: url1, port: port );
	url2 = dir + "/index.html";
	buf2 = http_get_cache( item: url2, port: port );
	if(!buf1 && !buf2){
		continue;
	}
	if(concl = egrep( string: buf1, pattern: "^(server\\s*:\\s*SAP NetWeaver Application Server [^/]*/ AS Java|\\s+<title>SAP NetWeaver Application Server Java</title>)", icase: TRUE )){
		found = TRUE;
		concluded = chomp( concl );
		conclUrl = http_report_vuln_url( port: port, url: url1, url_only: TRUE );
	}
	if(concl = egrep( string: buf2, pattern: "^(server\\s*:\\s*SAP NetWeaver Application Server [^/]*/ AS Java|\\s+<title>SAP NetWeaver Application Server Java</title>)", icase: TRUE )){
		found = TRUE;
		if(concluded){
			concluded += "\n";
		}
		concluded += chomp( concl );
		if(conclUrl){
			conclUrl += "\n";
		}
		conclUrl += http_report_vuln_url( port: port, url: url2, url_only: TRUE );
	}
	if(found){
		version = "unknown";
		set_kb_item( name: "sap/netweaver/as_java/detected", value: TRUE );
		set_kb_item( name: "sap/netweaver/as_java/http/detected", value: TRUE );
		set_kb_item( name: "sap/netweaver/as_java/port", value: port );
		set_kb_item( name: "sap/netweaver/as_java/location", value: location );
		set_kb_item( name: "sap/netweaver/as_java_or_portal/detected", value: TRUE );
		set_kb_item( name: "sap/netweaver/as_java_or_portal/http/detected", value: TRUE );
		set_kb_item( name: "sap/netweaver/as/detected", value: TRUE );
		set_kb_item( name: "sap/netweaver/as/http/detected", value: TRUE );
		ver = eregmatch( string: concluded, pattern: "server\\s*:\\s*SAP NetWeaver Application Server [^/]*/ AS Java ([0-9.]+)", icase: TRUE );
		if(!isnull( ver[1] )){
			version = ver[1];
		}
		register_and_report_cpe( app: "SAP NetWeaver Application Server (AS) Java", ver: version, concluded: concluded, base: "cpe:/a:sap:netweaver_application_server_java:", expr: "([0-9.]+)", insloc: location, regPort: port, regService: "www", conclUrl: conclUrl );
		exit( 0 );
	}
}
exit( 0 );

