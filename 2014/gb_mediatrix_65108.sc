if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103900" );
	script_bugtraq_id( 65108 );
	script_cve_id( "CVE-2014-1612" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Mediatrix 4402 Web Management Interface 'login' Page Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/65108" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-02-04 14:02:25 +0100 (Tue, 04 Feb 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Mbedthis-Appweb/banner" );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This can allow the attacker to steal cookie-based authentication
  credentials and launch other attacks." );
	script_tag( name: "vuldetect", value: "Send a special crafted HTTP request and check the
  response." );
	script_tag( name: "insight", value: "Reflected cross-site scripting (XSS) vulnerability in
  Mediatrix Web Management Interface, found in the login page, allows
  remote attackers to inject arbitrary web scripts or HTML via the
  vulnerable parameter 'username'" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "Mediatrix 4402 is prone to a cross-site scripting vulnerability
  because it fails to properly sanitize user-supplied input." );
	script_tag( name: "affected", value: "Mediatrix 4402 running firmware Dgw 1.1.13.186 is vulnerable. Other
  versions may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Mbedthis-Appweb" )){
	exit( 0 );
}
if(http_vuln_check( port: port, url: "/login.esp", pattern: "<title>Mediatrix</title>|Media5 Corporation", usecache: TRUE )){
	url = "/login.esp?r=system_info.esp&username=\"/><script>alert(/vt-xss-test/)</script>";
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/vt-xss-test/\\)</script>", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

