if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902412" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-04-26 15:24:49 +0200 (Tue, 26 Apr 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "OracleJSP Demos Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.gossamer-threads.com/lists/fulldisc/full-disclosure/79673" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/100650/cybsecoraclejsp-xss.txt" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuapr2011-301950.html" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to execute arbitrary scripts
  or actions written by an attacker. In addition, an attacker may obtain
  authorization cookies that would allow him to gain unauthorized access to
  the application." );
	script_tag( name: "affected", value: "OracleJSP Demos version 1.1.2.4.0 with iAS v1.0.2.2" );
	script_tag( name: "insight", value: "The flaws are due to failure in the,

  - '/demo/sql/index.jsp' script to properly sanitize user supplied input in
    'connStr' parameter.

  - '/demo/basic/hellouser/hellouser.jsp' script to properly sanitize
    user-supplied input in 'newName' parameter.

  - '/demo/basic/hellouser/hellouser_jml.jsp' script to properly sanitize
    user-supplied input in 'newName' parameter.

  - '/demo/basic/simple/welcomeuser.jsp' script to properly sanitize
    user-supplied input in 'user' parameter.

  - '/demo/basic/simple/usebean.jsp?' script to properly sanitize
    user-supplied input in 'newName' parameter." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running OracleJSP Demos and is prone to multiple
  cross site scripting vulnerabilities." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/ojspdemos", "/OracleJSP", "/OracleJSPDemos", "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.html" ), port: port );
	if(ContainsString( res, "OracleJSP Demo</" ) && ContainsString( res, "Oracle Corporation" )){
		req = http_get( item: NASLString( dir, "/sql/index.jsp?connStr=\"><script>" + "alert(\"XSS-TEST\")</script>" ), port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "><script>alert(\"XSS-TEST\")</script>" )){
			security_message( port );
			exit( 0 );
		}
	}
}

