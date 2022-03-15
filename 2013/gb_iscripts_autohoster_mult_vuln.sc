if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804165" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-7189", "CVE-2013-7190" );
	script_bugtraq_id( 64377, 64377 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-12-31 11:25:53 +0530 (Tue, 31 Dec 2013)" );
	script_name( "iScripts AutoHoster Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "The host is running iScripts AutoHoster and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is vulnerable
  or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "Multiple errors are due to:

  - Improper validation of user-supplied input to the 'checktransferstatus.php',
  'additionalsettings.php', 'payinvoiceothers.php', and 'checktransferstatusb
  ck.php' scripts through unspecified parameters.

  - Input passed via the 'tmpid' parameter to 'showtemplateimage.php' script,
  'fname' parameter to 'downloadfile.php' script, and the 'id' parameter to
  'csvdownload.php' script is not sanitised for requests using directory
  traversal attack (e.g., ../).

  - Improper validation of user-supplied input to the 'tldHoldList.php' script
  via 'fa' parameter." );
	script_tag( name: "affected", value: "iScripts AutoHoster version 2.4 and probably prior." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to read arbitrary files on the
  target system, obtain some sensitive information or execute arbitrary script
  code on the vulnerable server, perform SQL injection and compromise the
  application." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/89818" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/89816" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2013120103" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2013/Dec/att-121/iscripts.txt" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/iscripts-autohoster-php-code-injection" );
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
isPort = http_get_port( default: 80 );
if(!http_can_host_php( port: isPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/iscripts", "/autohoster", "/iscriptsautohoster", http_cgi_dirs( port: isPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	isRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: isPort );
	if(isRes && egrep( pattern: "Powered By.*iScripts.*Autohoster", string: isRes, icase: TRUE )){
		url = dir + "/admin/downloadfile.php?fname=../includes/config.php";
		if(http_vuln_check( port: isPort, url: url, pattern: "<?php", extra_check: make_list( "HOST.*\".*\"",
			 "DATABASE.*\".*\"",
			 "USER.*\".*\"",
			 "PASSWORD.*\".*\"" ) )){
			report = http_report_vuln_url( port: isPort, url: url );
			security_message( port: isPort, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

