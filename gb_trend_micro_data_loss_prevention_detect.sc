if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103181" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-06-14 13:57:36 +0200 (Tue, 14 Jun 2011)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Trend Micro Data Loss Prevention Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://us.trendmicro.com/us/products/enterprise/data-loss-prevention/index.html" );
	script_tag( name: "summary", value: "This host is running Trend Micro Data Loss Prevention, a network and
  endpoint-based data loss prevention (DLP) solution." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8443 );
url = "/dsc";
buf = http_get_cache( item: url + "/", port: port );
if(!buf){
	exit( 0 );
}
if(match = egrep( pattern: "<title>Trend Micro Data Loss Prevention Logon", string: buf, icase: TRUE )){
	version = "unknown";
	set_kb_item( name: "trendmicro/datalossprevention/detected", value: TRUE );
	register_and_report_cpe( app: "Trend Micro Data Loss Prevention", ver: version, concluded: match, conclUrl: url, base: "cpe:/a:trend_micro:data_loss_prevention:", expr: "^([0-9.]+)", insloc: url, regPort: port, regService: "www" );
}
exit( 0 );

