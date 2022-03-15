if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803182" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2013-1646", "CVE-2013-1647", "CVE-2013-1648", "CVE-2013-1650", "CVE-2013-1651" );
	script_bugtraq_id( 58465, 58473, 58475, 58469, 58470 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-03-18 10:14:58 +0530 (Mon, 18 Mar 2013)" );
	script_name( "Open-Xchange Server Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52603" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Mar/74" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/24791" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120785" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML or
  web script in a user's browser session in context of an affected site,
  compromise the application and access or modify data in the database." );
	script_tag( name: "affected", value: "Open-Xchange Server versions prior to 6.20.7-rev14, 6.22.0-rev13
  and 6.22.1-rev14." );
	script_tag( name: "insight", value: "- Input passed via arbitrary GET parameters to /servlet/TestServlet is not
    properly sanitized before being returned to the user.

  - Input related to the 'Source' field when creating subscriptions is not
    properly sanitized before being used. This can be exploited to perform
    arbitrary HTTP GET requests to remote and local servers.

  - The OXUpdater component does not properly validate the SSL certificate of
    an update server. This can be exploited to spoof update packages via a
    MitM (Man-in-the-Middle) attack.

  - The application creates the /opt/open-exchange/etc directory with insecure
    world-readable permissions. This can be exploited to disclose certain
    sensitive information.

  - Input passed via the 'location' GET parameter to /ajax/redirect is not
    properly sanitized before being used to construct HTTP response headers.

  - Certain input related to RSS feed contents is not properly sanitized before
    being used. This can be exploited to insert arbitrary HTML and script code." );
	script_tag( name: "solution", value: "Update to versions 6.20.7-rev14, 6.22.0-rev13, or 6.22.1-rev14." );
	script_tag( name: "summary", value: "This host is running Open-Xchange Server and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.open-xchange.com/home.html" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/ox6", "/Open-Xchange", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: dir + "/ox.html", port: port );
	rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
	if(ContainsString( rcvRes, ">Open-Xchange Server<" )){
		url = dir + "/servlet/TestServlet?foo=<script>alert(document.cookie)</script>";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

