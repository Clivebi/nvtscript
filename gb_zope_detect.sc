if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113570" );
	script_version( "2021-05-26T05:16:10+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 05:16:10 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2019-11-22 11:35:55 +0200 (Fri, 22 Nov 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Zope Application Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "zope/banner" );
	script_tag( name: "summary", value: "Checks whether Zope is present
  on the target system and if so, tries to figure out the installed version." );
	script_xref( name: "URL", value: "https://www.zope.org/world.html#application-servers" );
	exit( 0 );
}
CPE = "cpe:/a:zope:zope:";
require("cpe.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_remote_headers( port: port );
if(IsMatchRegexp( buf, "Server: *Zope" )){
	set_kb_item( name: "zope/detected", value: TRUE );
	version = "unknown";
	ver = eregmatch( string: buf, pattern: "Zope/[(]([0-9.]+)" );
	if(!isnull( ver[1] )){
		version = ver[1];
	}
	register_and_report_cpe( app: "Zope Application Server", ver: version, concluded: ver[0], base: CPE, expr: "([0-9.]+)", insloc: "/", regPort: port, regService: "www" );
}
exit( 0 );

