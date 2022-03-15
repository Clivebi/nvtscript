if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.13858" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-31T06:15:21+0000" );
	script_tag( name: "last_modification", value: "2020-08-31 06:15:21 +0000 (Mon, 31 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "osTicket Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 George A. Theall" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects whether the target is running osTicket and extracts
  version numbers and locations of any instances found.

  osTicket is a PHP-based open source support ticket system." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.osticket.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
lookup_table = make_array( "f4f5bc6", "1.14.3", "cba6035", "1.14.2", "f1e9e88", "1.14.1", "9ea8e77", "1.14", "4b9a699", "1.14-rc2", "c32990d", "1.14-rc1", "e351ba5", "1.12.6", "933bb1f", "1.12.5", "bd38765", "1.12.4", "bcf1a6f", "1.12.3", "a5d898b", "1.12.2", "a8c4f57", "1.12.1", "a076918", "1.12", "7b1eee8", "1.11", "e321982", "1.11.0-rc1", "dca01e1", "1.10.7", "91602a7", "1.10.6", "13f2f4a", "1.10.5", "035fd0a", "1.10.4", "b7ef532", "1.10.3", "8c848b5", "1.10.2", "9ae093d", "1.10.1", "901e5ea", "1.10", "907ec36", "1.10-rc.3", "231f11e", "1.10-rc.2", "f4a172f", "1.9.16", "70898b3", "1.9.15", "8b927a0", "1.9.14", "a6174db", "1.9.13", "19292ad", "1.9.12", "c1b5a33", "1.9.11", "a7d44f8", "1.9.9", "4752178", "1.9.8.1", "9c6acce", "1.9.8", "4be5782", "1.9.7", "9adad36", "1.9.6", "1faad22", "1.9.5.1", "c18eac4", "1.9.4", "ecb4f89", "1.9.5", "da684b9", "1.8.12", "d0f776f", "1.8.11", "0ce50e3", "1.8.10", "30738f9", "1.8.9", "7960e24", "1.8.8", "bdfece3", "1.8.7", "481c83e", "1.8.6" );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/osticket", "/osTicket", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/open.php";
	res = http_get_cache( port: port, item: url );
	if(egrep( pattern: "alt=\"osTicket", string: res, icase: TRUE ) || IsMatchRegexp( res, "(P|p)owered by osTicket" )){
		version = "unknown";
		pat = "alt=.osTicket STS v(.+) *$";
		matches = egrep( pattern: pat, string: res );
		for match in split( matches ) {
			match = chomp( match );
			ver = eregmatch( pattern: pat, string: match );
			if(isnull( ver )){
				break;
			}
			version = ver[1];
			concl = ver[0];
			if(version == "1.2"){
				if( ContainsString( res, "Copyright &copy; 2003-2004 osTicket.com" ) ){
					url = dir + "/include/admin_login.php";
					req = http_get( item: url, port: port );
					res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
					if( ContainsString( res, "<td>Please login:</td>" ) ){
						version = "1.3.0";
					}
					else {
						if( ContainsString( res, "Invalid path" ) ){
							version = "1.3.1";
						}
						else {
							version = "unknown";
						}
					}
				}
				else {
					url = dir + "/attachments.php";
					req = http_get( item: url, port: port );
					res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
					if( ContainsString( res, "You do not have access to attachments" ) ){
						version = "1.2.7";
					}
					else {
						if(ContainsString( res, "404 Not Found" )){
							version = "1.2.5";
						}
					}
				}
			}
		}
		if(version == "unknown"){
			buf = eregmatch( pattern: "\\.(css|js)\\?([0-9a-f]{7})", string: res );
			if(!isnull( buf[2] )){
				version_hash = buf[2];
				for hash in keys( lookup_table ) {
					if(hash == version_hash){
						version = lookup_table[hash];
						concl = "Lookup of Git Hash: " + version_hash;
						break;
					}
				}
			}
		}
		set_kb_item( name: "osticket/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:osticket:osticket:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:osticket:osticket";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "osTicket", version: version, install: install, cpe: cpe, concluded: concl ), port: port );
		exit( 0 );
	}
}
exit( 0 );

