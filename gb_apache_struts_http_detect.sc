if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800276" );
	script_version( "2021-04-01T11:05:36+0000" );
	script_tag( name: "last_modification", value: "2021-04-01 11:05:36 +0000 (Thu, 01 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Apache Struts Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Apache Struts." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 8080 );
var found_page;
for dir in nasl_make_list_unique( "/", "/struts", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for subdir in make_list( dir,
		 dir + "/docs/docs",
		 dir + "/docs" ) {
		url0 = subdir + "/index.html";
		concl_url0 = http_report_vuln_url( port: port, url: url0, url_only: TRUE );
		res0 = http_get_cache( item: url0, port: port );
		for file in make_list( subdir + "/struts2-core-apidocs/help-doc.html",
			 subdir + "/struts2-core-apidocs/overview-summary.html",
			 subdir + "/struts2-core-apidocs/index-all.html" ) {
			res1 = http_get_cache( item: file, port: port );
			if(res1 && IsMatchRegexp( res1, "^HTTP/1\\.[01] 200" ) && ContainsString( res1, "Struts 2 Core" )){
				concl_url1 = http_report_vuln_url( port: port, url: file, url_only: TRUE );
				break;
			}
		}
		for url2 in make_list( dir + "/src/pom.xml",
			 dir + "/src/apps/pom.xml" ) {
			res2 = http_get_cache( item: url2, port: port );
			if(res2 && IsMatchRegexp( res2, "^HTTP/1\\.[01] 200" ) && ContainsString( res2, "<name>Struts 2" )){
				concl_url2 = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
				break;
			}
		}
		for url3 in make_list( subdir + "/WW/cwiki.apache.org/WW/home.html",
			 subdir + "/home.html" ) {
			res3 = http_get_cache( item: url3, port: port );
			if(res3 && IsMatchRegexp( res3, "^HTTP/1\\.[01] 200" )){
				concl_url3 = http_report_vuln_url( port: port, url: url3, url_only: TRUE );
				break;
			}
		}
		for url4 in make_list( subdir + "/WW/cwiki.apache.org/WW/guides.html",
			 subdir + "/guides.html" ) {
			res4 = http_get_cache( item: url4, port: port );
			if(res4 && IsMatchRegexp( res4, "^HTTP/1\\.[01] 200" )){
				concl_url4 = http_report_vuln_url( port: port, url: url4, url_only: TRUE );
				break;
			}
		}
	}
	url5 = dir + "/src/src/site/xdoc/index.xml";
	concl_url5 = http_report_vuln_url( port: port, url: url5, url_only: TRUE );
	res5 = http_get_cache( item: url5, port: port );
	url6 = dir + "/utils.js";
	concl_url6 = http_report_vuln_url( port: port, url: url6, url_only: TRUE );
	res6 = http_get_cache( item: url6, port: port );
	for url7 in make_list( dir,
		 dir + "/struts2-blank",
		 dir + "/struts2-basic",
		 dir + "/struts2-mailreader",
		 dir + "/struts2-portlet",
		 dir + "/struts2-rest-showcase",
		 dir + "/struts2-showcase",
		 dir + "/struts-cookbook",
		 dir + "/struts-examples" ) {
		if( ContainsString( url7, "/struts2-blank" ) ) {
			pages = make_list( url7 + "/example/HelloWorld.action" );
		}
		else {
			if( ContainsString( url7, "/struts2-mailreader" ) ) {
				pages = make_list( url7 + "/Welcome.do" );
			}
			else {
				if( ContainsString( url7, "/struts2-showcase" ) ) {
					pages = make_list( url7 + "/showcase.action" );
				}
				else {
					pages = make_list( url7 + "/example/HelloWorld.action",
						 url7 + "/Welcome.do",
						 url7 + "/showcase.action",
						 url7 + "/index.action" );
				}
			}
		}
		for page in pages {
			res7 = http_get_cache( item: page, port: port );
			if(res7 && IsMatchRegexp( res7, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res7, "Struts2" ) || ContainsString( res7, "Apache Struts" ) || egrep( string: res7, pattern: ">Struts2? (Cookbook|Examples|Showcase)<", icase: FALSE ) )){
				found_page = TRUE;
				concl_url7 = http_report_vuln_url( port: port, url: page, url_only: TRUE );
				break;
			}
		}
		if(found_page){
			break;
		}
	}
	if(res0 && IsMatchRegexp( res0, "^HTTP/1\\.[01] 200" ) && ContainsString( res0, "Struts" ) && ( ContainsString( res0, "Apache" ) || ContainsString( res0, "apache" ) )){
		found = TRUE;
		concl_url = concl_url0;
	}
	if(res1 && IsMatchRegexp( res1, "^HTTP/1\\.[01] 200" ) && ContainsString( res1, "Struts 2 Core" ) && ( ContainsString( res1, "title>API Help" ) || ContainsString( res1, "\"overviewSummary\"" ) || IsMatchRegexp( res1, "apache\\.struts2" ) )){
		found = TRUE;
		if(concl_url){
			concl_url += "\n";
		}
		concl_url += concl_url1;
	}
	if(res2 && IsMatchRegexp( res2, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res2, ">Apache Struts 2<" ) || ContainsString( res2, ">Struts 2 Webapps<" ) )){
		found = TRUE;
		if(concl_url){
			concl_url += "\n";
		}
		concl_url += concl_url2;
	}
	if(res3 && IsMatchRegexp( res3, "^HTTP/1\\.[01] 200" ) && ContainsString( res3, "Getting Started" ) && ContainsString( res3, "Home" ) && ContainsString( res3, "Distributions" )){
		found = TRUE;
		if(concl_url){
			concl_url += "\n";
		}
		concl_url += concl_url3;
	}
	if(res4 && IsMatchRegexp( res4, "^HTTP/1\\.[01] 200" ) && ContainsString( res4, "Migration Guide" ) && ContainsString( res4, "Core Developers Guide" ) && ContainsString( res4, "Release Notes" )){
		found = TRUE;
		if(concl_url){
			concl_url += "\n";
		}
		concl_url += concl_url4;
	}
	if(res5 && IsMatchRegexp( res5, "^HTTP/1\\.[01] 200" ) && ContainsString( res5, "Apache Struts" )){
		found = TRUE;
		if(concl_url){
			concl_url += "\n";
		}
		concl_url += concl_url5;
	}
	if(res6 && IsMatchRegexp( res6, "^HTTP/1\\.[01] 200" ) && ContainsString( res6, "var StrutsUtils =" )){
		found = TRUE;
		if(concl_url){
			concl_url += "\n";
		}
		concl_url += concl_url6;
	}
	if(res7 && IsMatchRegexp( res7, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res7, "Struts2" ) || ContainsString( res7, "Apache Struts" ) || egrep( string: res7, pattern: ">Struts2? (Cookbook|Examples|Showcase)<", icase: FALSE ) )){
		found = TRUE;
		if(concl_url){
			concl_url += "\n";
		}
		concl_url += concl_url7;
	}
	if(found){
		strutsVersion = "unknown";
		strutsVer = eregmatch( pattern: "Struts 2 Core ([0-9.]+) API", string: res1 );
		if(strutsVer[1]){
			strutsVersion = strutsVer[1];
		}
		if(strutsVersion == "unknown"){
			strutsdata = eregmatch( pattern: "<modelVersion(.*)<packaging>", string: res2 );
			strutsVer = eregmatch( pattern: "<version>([0-9.]+)</version>", string: strutsdata[1] );
			if(strutsVer[1]){
				strutsVersion = strutsVer[1];
			}
		}
		if(strutsVersion == "unknown"){
			strutsVer = eregmatch( pattern: ">Version Notes ([0-9]+\\.[0-9]+\\.[0-9.]+)", string: res4 );
			if(strutsVer[1] && version_is_less( version: strutsVer[1], test_version: "2.5.10.1" )){
				strutsVersion = strutsVer[1];
			}
		}
		if(strutsVersion == "unknown"){
			strutsVer = eregmatch( pattern: "Release Notes ([0-9]+\\.[0-9]+\\.[0-9.]+)", string: res3 );
			if(strutsVer[1]){
				strutsVersion = strutsVer[1];
			}
		}
		if(strutsVersion == "unknown"){
			strutsVer = eregmatch( pattern: "Release Notes ([0-9]+\\.[0-9]+\\.[0-9.]+)", string: res4 );
			if(strutsVer[1] && version_is_less( version: strutsVer[1], test_version: "2.0.14" )){
				strutsVersion = strutsVer[1];
			}
		}
		if(strutsVersion == "unknown"){
			strutsVer = eregmatch( pattern: ">version ([0-9]+\\.[0-9]+\\.[0-9.]+)", string: res5 );
			if(strutsVer[1]){
				strutsVersion = strutsVer[1];
			}
		}
		if(strutsVersion == "unknown"){
			strutsVer = eregmatch( pattern: "Struts2 ([0-9]+\\.[0-9]+\\.[0-9.]+)", string: res7 );
			if(strutsVer[1]){
				strutsVersion = strutsVer[1];
			}
		}
		set_kb_item( name: "apache/struts/detected", value: TRUE );
		set_kb_item( name: "apache/struts/http/detected", value: TRUE );
		set_kb_item( name: "apache/struts/http/" + port + "/installs", value: port + "#---#" + install + "#---#" + strutsVersion + "#---#" + strutsVer[0] + "#---##---#" + concl_url );
		exit( 0 );
	}
}
exit( 0 );

