if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805346" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-03-03 17:44:58 +0530 (Tue, 03 Mar 2015)" );
	script_name( "NetCat CMS Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "The host is installed with NetCat CMS
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP
  GET and check whether it redirects to the malicious website." );
	script_tag( name: "insight", value: "Multiple flaws are due to input
  passed via,

  - 'redirect_url' parameter to 'netshop/post.php' is not properly validated.

  - 'site' parameter to 'modules/redir/?' is not properly validated.

  - 'url' parameter to 'redirect.php?' is not properly validated." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to arbitrary URL redirection, disclosure or modification of sensitive
  data." );
	script_tag( name: "affected", value: "NetCat CMS version 5.01, 3.12, 3.0, 2.4,
  2.3, 2.2, 2.1, 2.0 and 1.1" );
	script_tag( name: "solution", value: "Update to NetCat CMS 5.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "exploit" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Mar/8" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Mar/9" );
	script_xref( name: "URL", value: "http://securityrelated.blogspot.in/2015/02/netcat-cms-multiple-url-redirection.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://netcat.ru" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
cmsPort = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/netcat", "/netcatcms", "/cms", http_cgi_dirs( port: cmsPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/" ), port: cmsPort );
	if(ContainsString( rcvRes, ">NetCat" )){
		url = dir + "/modules/redir/?&site=http://www.example.com";
		sndReq = http_get( item: url, port: cmsPort );
		rcvRes = http_keepalive_send_recv( port: cmsPort, data: sndReq );
		if(rcvRes && IsMatchRegexp( rcvRes, "HTTP/1.. 302" ) && IsMatchRegexp( rcvRes, "Location.*http://www.example.com" )){
			security_message( port: cmsPort );
			exit( 0 );
		}
	}
}
exit( 99 );

