if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140242" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-04-10 16:22:10 +0200 (Mon, 10 Apr 2017)" );
	script_name( "Trend Micro Interscan Web Security Virtual Appliance Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of the Trend Micro Interscan Web Security Virtual Appliance." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8443 );
buf = http_get_cache( port: port, item: "/logon.jsp" );
if(ContainsString( buf, "<title>Trend Micro InterScan Web Security Virtual Appliance</title>" ) && ContainsString( buf, "uilogonsubmit.jsp" )){
	version = "unknown";
	build = "unknown";
	set_kb_item( name: "trendmicro/IWSVA/detected", value: TRUE );
	set_kb_item( name: "trendmicro/IWSVA/http/detected", value: TRUE );
	set_kb_item( name: "trendmicro/IWSVA/http/port", value: port );
	url = "/html/about.htm";
	res = http_get_cache( port: port, item: url );
	vers = eregmatch( pattern: "Trend Micro InterScan Web Security Virtual Appliance ([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "trendmicro/IWSVA/http/" + port + "/concluded", value: vers[0] );
		set_kb_item( name: "trendmicro/IWSVA/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
	}
	set_kb_item( name: "trendmicro/IWSVA/http/" + port + "/version", value: version );
	set_kb_item( name: "trendmicro/IWSVA/http/" + port + "/build", value: build );
}
exit( 0 );

