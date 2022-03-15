if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803316" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2013-1466" );
	script_bugtraq_id( 58058 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-03-01 11:22:26 +0530 (Fri, 01 Mar 2013)" );
	script_name( "glFusion Multiple Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/24536" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB23142" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120423/glFusion-1.2.2-Cross-Site-Scripting.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to execute arbitrary code
  in the browser to steal cookie-based authentication credentials and launch
  other attacks." );
	script_tag( name: "affected", value: "glFusion version 1.2.2 and prior" );
	script_tag( name: "insight", value: "The flaws are due

  - Insufficient filtration of user data in URL after
    '/admin/plugins/mediagallery/xppubwiz.php'

  - Insufficient filtration of user data passed to '/profiles.php',
    '/calendar/index.php' and '/links/index.php' via following parameters,
    'subject', 'title', 'url', 'address1', 'address2', 'calendar_type', 'city',
    'state', 'title', 'url', 'zipcode'." );
	script_tag( name: "solution", value: "Upgrade to the latest version of glFusion 1.2.2.pl4 or later." );
	script_tag( name: "summary", value: "This host is running glFusion and is prone to multiple cross-site
  scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.glfusion.org/filemgmt/index.php" );
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
for dir in nasl_make_list_unique( "/", "/glfusion", "/fusion", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: NASLString( dir, "/index.php" ), port: port );
	if(ContainsString( res, ">glFusion" )){
		url = dir + "/admin/plugins/mediagallery/xppubwiz.php/" + "><script>alert(document.cookie)</script>";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: make_list( "User Name",
			 "Password" ) )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

