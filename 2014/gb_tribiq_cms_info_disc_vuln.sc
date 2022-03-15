if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805232" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2011-2727" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-12-31 15:18:53 +0530 (Wed, 31 Dec 2014)" );
	script_name( "Tribiq CMS Direct Request Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Tribiq CMS
  and is prone to information disclosure vulnerability" );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check
  whether it is possible to read full path to installation directory" );
	script_tag( name: "insight", value: "The error exists as application reveals
  the full path to installation directory in an error message." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain knowledge of the web root directory and other potentially
  sensitive information." );
	script_tag( name: "affected", value: "Tribiq CMS version 5.2.7b and probably
  prior." );
	script_tag( name: "solution", value: "Upgrade to Tribiq CMS version 5.2.7c or
  later." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.htbridge.com/advisory/HTB22857" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://sourceforge.net/projects/tribiq" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
cmsPort = http_get_port( default: 80 );
if(!http_can_host_php( port: cmsPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/community", "/tribiqcms", "/cms", http_cgi_dirs( port: cmsPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: NASLString( dir, "/admin/welcome.php" ), port: cmsPort );
	rcvRes = http_keepalive_send_recv( port: cmsPort, data: sndReq );
	if(rcvRes && IsMatchRegexp( rcvRes, ">Welcome to Tribiq CMS<" )){
		url = dir + "/cmsjs/plugin.js.php";
		sndReq = http_get( item: url, port: cmsPort );
		rcvRes = http_keepalive_send_recv( port: cmsPort, data: sndReq );
		if(rcvRes && IsMatchRegexp( rcvRes, ">Warning<.*Invalid argument.*in <b" )){
			security_message( port: cmsPort );
			exit( 0 );
		}
	}
}
exit( 99 );

