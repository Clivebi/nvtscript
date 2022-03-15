if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12643" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Horde IMP Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 George A. Theall" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.horde.org/imp/" );
	script_tag( name: "summary", value: "This script detects whether the remote host is running Horde IMP
  and extracts version numbers and locations of any instances found.

  IMP is a PHP-based webmail package from The Horde Project that provides
  access to mail accounts via POP3 or IMAP." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
check_files = make_array( "/services/help/?module=imp&show=about", ">This is Imp .{0,3}\\(?([0-9.]+)\\)?\\.<", "/docs/CHANGES", "^ *v([0-9.]+) *-?(RC[0-9]|BETA|cvs)$", "/test.php", "^ *<li>IMP: +([0-9.]+) *</li> *$", "/README", "^Version +([0-9.]+) *$", "/lib/version.phps", "IMP_VERSION', '([0-9.]+)'", "/status.php3", ">IMP, Version ([0-9.]+)<" );
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/webmail", "/horde", "/horde/imp", "/email", "/imp", "/mail", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	res = http_get_cache( port: port, item: url );
	if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, "<!-- IMP: Copyright" ) || ContainsString( res, "document.imp_login.imapuser.value" ) || ContainsString( res, "document.imp_login.loginButton.disabled" ) || ContainsString( res, "IMP: http://horde.org/imp/" ) )){
		set_kb_item( name: "horde/imp/detected", value: TRUE );
		version = "unknown";
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		for check_file in keys( check_files ) {
			pattern = check_files[check_file];
			url = dir + check_file;
			res = http_get_cache( item: url, port: port );
			if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && match = egrep( pattern: pattern, string: res, icase: FALSE )){
				if( ContainsString( url, "/docs/CHANGES" ) ){
					for _match in split( match ) {
						_match = chomp( _match );
						vers = eregmatch( pattern: pattern, string: _match );
						if(vers[1]){
							break;
						}
					}
				}
				else {
					vers = eregmatch( pattern: pattern, string: match );
				}
				if(vers[1]){
					conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
					version = vers[1];
					break;
				}
			}
		}
		register_and_report_cpe( app: "Horde IMP", ver: version, concluded: vers[0], conclUrl: conclUrl, base: "cpe:/a:horde:imp:", expr: "^([0-9.]+)", insloc: install, regPort: port );
	}
}
exit( 0 );

