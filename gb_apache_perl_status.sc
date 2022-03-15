if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117537" );
	script_version( "2021-07-19T13:17:53+0000" );
	script_tag( name: "last_modification", value: "2021-07-19 13:17:53 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-06 12:14:06 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Apache HTTP Server 'mod_perl' /perl-status accessible (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://perl.apache.org/docs/2.0/api/Apache2/Status.html" );
	script_tag( name: "summary", value: "Requesting the URI /perl-status provides a comprehensive
  overview of the server configuration." );
	script_tag( name: "insight", value: "perl-status is a Apache HTTP Server handler provided by the
  'mod_perl' module and used to retrieve the server's configuration." );
	script_tag( name: "impact", value: "Requesting the URI /perl-status gives throughout information
  about the currently running Apache to an attacker." );
	script_tag( name: "affected", value: "All Apache installations with an enabled 'mod_perl' module." );
	script_tag( name: "vuldetect", value: "Checks if the /perl-status page of Apache is accessible." );
	script_tag( name: "solution", value: "- If this feature is unused commenting out the appropriate
  section in the web servers configuration is recommended.

  - If this feature is used restricting access to trusted clients is recommended." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/perl-status";
buf = http_get_cache( item: url, port: port );
if(buf && IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && egrep( string: buf, pattern: "^\\s*(<title>Apache2::Status[^<]+</title>|Embedded Perl version.+for.+Apache)", icase: FALSE )){
	set_kb_item( name: "apache/perl-status/detected", value: TRUE );
	set_kb_item( name: "apache/perl-status/" + port + "/detected", value: TRUE );
	set_kb_item( name: "mod_jk_or_apache_status_info_error_pages/banner", value: TRUE );
	set_kb_item( name: "mod_perl_or_apache_status_info_error_pages/banner", value: TRUE );
	set_kb_item( name: "mod_python_or_apache_status_info_error_pages/banner", value: TRUE );
	set_kb_item( name: "mod_ssl_or_apache_status_info_error_pages/banner", value: TRUE );
	set_kb_item( name: "openssl_or_apache_status_info_error_pages/banner", value: TRUE );
	set_kb_item( name: "perl_or_apache_status_info_error_pages/banner", value: TRUE );
	set_kb_item( name: "python_or_apache_status_info_error_pages/banner", value: TRUE );
	sv = eregmatch( pattern: "Embedded Perl version <b>(v[^<]+)</b> for <b>(Apache/[^<]+)</b>", string: buf );
	if(sv[1]){
		banner = "Server: " + chomp( sv[2] );
		if(!ContainsString( sv[2], "Perl" )){
			banner += " Perl/" + sv[1];
		}
		set_kb_item( name: "www/perl-status/banner/" + port, value: banner );
		set_kb_item( name: "www/perl-status/banner/concluded/" + port, value: chomp( sv[0] ) );
	}
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

