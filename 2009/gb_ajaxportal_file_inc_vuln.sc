if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800817" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-2262" );
	script_name( "AjaxPortal 'di.php' File Inclusion Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/504618/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ajaxportal_detect.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ajaxportal/detected" );
	script_tag( name: "impact", value: "Successful exploitation will let the remote attacker to execute
  arbitrary PHP code via a URL in the pathtoserverdata parameter." );
	script_tag( name: "affected", value: "MyioSoft, AjaxPortal version 3.0." );
	script_tag( name: "insight", value: "The flaw is due to error in the 'pathtoserverdata' parameter in
  install/di.php and it can exploited to cause PHP remote file inclusion." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running AjaxPortal and is prone to File Inclusion
  vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("version_func.inc.sc");
ajaxPort = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/ajaxportal", "/portal", http_cgi_dirs( port: ajaxPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/install/index.php", port: ajaxPort );
	if(IsMatchRegexp( rcvRes, "MyioSoft EasyInstaller" ) && egrep( pattern: "^HTTP/1\\.[01] 200", string: rcvRes )){
		ajaxVer = get_kb_item( "www/" + ajaxPort + "/AjaxPortal" );
		ajaxVer = eregmatch( pattern: "^(.+) under (/.*)$", string: ajaxVer );
		if(ajaxVer[1] != NULL){
			if(version_is_equal( version: ajaxVer[1], test_version: "3.0" )){
				security_message( port: ajaxPort );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

