if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108751" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2020-04-17 11:38:17 +0000 (Fri, 17 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "CentOS WebPanel (CWP) Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 2030, 2082, 2083, 2086, 2087 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://centos-webpanel.com/" );
	script_tag( name: "summary", value: "Detection of CentOS WebPanel (CWP).

  The script sends a connection request to the server and attempts to detect CentOS WebPanel (CWP)." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 2030 );
res = http_get_cache( port: port, item: "/" );
res2 = http_get_cache( port: port, item: "/login/index.php" );
if(IsMatchRegexp( res, "Server\\s*:\\s*cwpsrv" ) || IsMatchRegexp( res2, "Server\\s*:\\s*cwpsrv" ) || egrep( string: res, pattern: "Powered by.* CentOS-WebPanel", icase: TRUE ) || ( ContainsString( res, "<title>CWP | User</title>" ) && ContainsString( res, "cwp_theme" ) ) || IsMatchRegexp( res, "<a href=\"https?://(www\\.)?control-webpanel\\.com\" target=\"_blank\">CWP Control WebPanel\\.</a>" ) || IsMatchRegexp( res2, "<a href=\"https?://(www\\.)?centos-webpanel\\.com\" target=\"_blank\">CentOS WebPanel</a>" ) || ContainsString( res2, "<title>Login | CentOS WebPanel</title>" )){
	version = "unknown";
	cpe = "cpe:/a:centos-webpanel:centos_web_panel";
	set_kb_item( name: "centos_webpanel/detected", value: TRUE );
	os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", desc: "CentOS WebPanel (CWP) Detection (HTTP)", runs_key: "unixoide" );
	os_register_and_report( os: "Red Hat Enterprise Linux", cpe: "cpe:/o:redhat:enterprise_linux", desc: "CentOS WebPanel (CWP) Detection (HTTP)", runs_key: "unixoide" );
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "CentOS WebPanel (CWP)", version: version, install: "/", cpe: cpe ), port: port );
}
exit( 0 );

