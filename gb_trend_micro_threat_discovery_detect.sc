if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113764" );
	script_version( "2020-10-08T13:07:46+0000" );
	script_tag( name: "last_modification", value: "2020-10-08 13:07:46 +0000 (Thu, 08 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-29 12:29:00 +0200 (Tue, 29 Sep 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Trend Micro Threat Discovery Appliance Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Checks whether the target is a Trend Micro Threat Discovery Appliance." );
	script_xref( name: "URL", value: "https://docs.trendmicro.com/all/ent/tms/v2.6/en-us/tda_2.6_olh/help/intro/about_threat_discovery_appliance.htm" );
	exit( 0 );
}
CPE = "cpe:/a:trendmicro:threat_discovery:";
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_cache( port: port, item: "/" );
if(IsMatchRegexp( buf, "title>Trend Micro Threat Discovery Appliance Logon</title>" ) && IsMatchRegexp( buf, "Trend Micro Incorporated" )){
	version = "unknown";
	set_kb_item( name: "trendmicro/threat_discovery/detected", value: TRUE );
	register_and_report_cpe( app: "Trend Micro Thread Discovery Appliance", ver: version, base: CPE, expr: "([0-9.]+)", insloc: port + "/tcp", regPort: port, regProto: "tcp", conclUrl: "/" );
}
exit( 0 );

