if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10677" );
	script_version( "2021-07-19T12:32:02+0000" );
	script_cve_id( "CVE-2020-25073" );
	script_tag( name: "last_modification", value: "2021-07-19 12:32:02 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-11 16:20:00 +0000 (Fri, 11 Sep 2020)" );
	script_name( "Apache HTTP Server /server-status accessible (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 StrongHoldNet" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://httpd.apache.org/docs/current/mod/mod_status.html" );
	script_tag( name: "summary", value: "Requesting the URI /server-status provides information on the
  server activity and performance." );
	script_tag( name: "insight", value: "server-status is a Apache HTTP Server handler provided by the
  'mod_status' module and used to retrieve the server's activity and performance." );
	script_tag( name: "impact", value: "Requesting the URI /server-status gives throughout information
  about the currently running Apache to an attacker." );
	script_tag( name: "affected", value: "- All Apache installations with an enabled 'mod_status' module

  - FreedomBox through 20.13" );
	script_tag( name: "vuldetect", value: "Checks if the /server-status page of Apache is accessible." );
	script_tag( name: "solution", value: "- If this feature is unused commenting out the appropriate
  section in the web servers configuration is recommended

  - If this feature is used restricting access to trusted clients is recommended

  - If the FreedomBox software is running on the target update the software to a later version" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/server-status";
buf = http_get_cache( item: url, port: port );
if(buf && IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, ">Apache Server Status" ) || ContainsString( buf, "title>Apache Status</title>" ) )){
	set_kb_item( name: "apache/server-status/detected", value: TRUE );
	set_kb_item( name: "apache/server-status/" + port + "/detected", value: TRUE );
	set_kb_item( name: "mod_jk_or_apache_status_info_error_pages/banner", value: TRUE );
	set_kb_item( name: "mod_perl_or_apache_status_info_error_pages/banner", value: TRUE );
	set_kb_item( name: "mod_python_or_apache_status_info_error_pages/banner", value: TRUE );
	set_kb_item( name: "mod_ssl_or_apache_status_info_error_pages/banner", value: TRUE );
	set_kb_item( name: "openssl_or_apache_status_info_error_pages/banner", value: TRUE );
	set_kb_item( name: "perl_or_apache_status_info_error_pages/banner", value: TRUE );
	set_kb_item( name: "python_or_apache_status_info_error_pages/banner", value: TRUE );
	sv = eregmatch( pattern: "Server Version: (Apache/[^<]+)", string: buf );
	if(sv[1]){
		set_kb_item( name: "www/server-status/banner/" + port, value: "Server: " + chomp( sv[1] ) );
		set_kb_item( name: "www/server-status/banner/concluded/" + port, value: chomp( sv[0] ) );
	}
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

