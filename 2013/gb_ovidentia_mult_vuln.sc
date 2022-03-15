if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803876" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-08-22 11:58:24 +0530 (Thu, 22 Aug 2013)" );
	script_name( "Ovidentia Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running Ovidentia and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to
  read the cookie or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "Input passed via several parameters is not properly sanitized before being
  returned to the user or before used in SQL queries." );
	script_tag( name: "affected", value: "Ovidentia version 7.9.4, other versions may also be affected." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML or
  script code in a user's browser session in the context of an affected site
  or manipulate SQL queries by injecting arbitrary SQL code." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://hardeningsecurity.com/?p=609" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/122896" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/codes/ovidentia_multiple.txt" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5154.php" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/ovidentia-794-cross-site-scripting-sql-injection" );
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
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/ovidentia", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(ContainsString( res, ">Ovidentia" ) && ContainsString( res, ">Groupware Portal" )){
		url = dir + "/index.php?idx=displayGanttChart&iIdOwner" + "=1_</script><script>alert(document.cookie" + ")</script>&iIdProject=-1&tg=usrTskMgr";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: make_list( ">Gantt view",
			 ">My tasks" ) )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

