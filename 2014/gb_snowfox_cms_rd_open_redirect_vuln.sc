if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805208" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-9343" );
	script_bugtraq_id( 71174 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-12-11 18:21:19 +0530 (Thu, 11 Dec 2014)" );
	script_name( "Snowfox CMS 'rd' Parameter Open Redirect Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Snowfox CMS
  and is prone to open redirect vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted HTTP GET request and check
  whether it redirects to the malicious websites." );
	script_tag( name: "insight", value: "The error exists as the application does
  not validate the 'rd' parameter upon submission to the selectlanguage.class.php
  script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to create a specially crafted URL, that if clicked, would redirect
  a victim from the intended legitimate web site to an arbitrary web site of the
  attacker's choosing." );
	script_tag( name: "affected", value: "Snowfox CMS version 1.0" );
	script_tag( name: "solution", value: "Upgrade to Snowfox CMS version 1.0.10 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/codes/snowfox_url.txt" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/129162" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.snowfoxcms.org/" );
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
for dir in nasl_make_list_unique( "/", "/snowfox", "/snowfoxcms", "/cms", http_cgi_dirs( port: cmsPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: cmsPort );
	if(rcvRes && IsMatchRegexp( rcvRes, "powered by.*>Snowfox CMS<" )){
		url = dir + "/?uri=user/select-language&formAction=submit&rd=ht" + "tp://www.example.com";
		sndReq = http_get( item: url, port: cmsPort );
		rcvRes = http_keepalive_send_recv( port: cmsPort, data: sndReq );
		if(rcvRes && IsMatchRegexp( rcvRes, "HTTP/1.. 302" ) && IsMatchRegexp( rcvRes, "(L|l)ocation: http://www.example.com" )){
			security_message( port: cmsPort );
			exit( 0 );
		}
	}
}
exit( 99 );

