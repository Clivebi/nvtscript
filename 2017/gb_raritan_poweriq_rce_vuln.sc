CPE = "cpe:/a:raritan:power_iq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106818" );
	script_version( "2020-11-12T10:32:48+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 10:32:48 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-05-22 15:05:20 +0700 (Mon, 22 May 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Raritan PowerIQ Rails RCE Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_raritan_poweriq_detect.sc" );
	script_mandatory_keys( "raritan_poweriq/detected" );
	script_tag( name: "summary", value: "Raritan PowerIQ is prone to a remote code execution vulnerability." );
	script_tag( name: "insight", value: "Raritan PowerIQ versions 4.1, 4.2, and 4.3 ship with a Rails 2 web interface
  with a hardcoded session secret of 8e238c9702412d475a4c44b7726a0537." );
	script_tag( name: "impact", value: "An unauthenticated attacker may execute arbitrary code as the nginx user." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP request and checks the response." );
	script_tag( name: "affected", value: "Raritran PowerIQ version 4.1, 4.2 and 4.3." );
	script_tag( name: "solution", value: "Upgrade to the latest version." );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/130797/raritanpoweriq-staticsecret.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
require("url_func.inc.sc");
require("string_hex_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
url = "/login/login";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req );
if(!ContainsString( res, "Set-Cookie: _session_id" )){
	exit( 99 );
}
cookie = eregmatch( pattern: "Set-Cookie: _session_id=([A-Za-z0-9%]*)--([0-9A-Fa-f]+);", string: res );
if(isnull( cookie[1] ) || isnull( cookie[2] )){
	exit( 99 );
}
data = urldecode( estr: cookie[1] );
SECRET = "8e238c9702412d475a4c44b7726a0537";
hash = hexstr( HMAC_SHA1( data: data, key: SECRET ) );
if(hash == cookie[2]){
	report = "It was possible to confirm that Rails uses the 'secret_token' '8e238c9702412d475a4c44b7726a0537'\\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

