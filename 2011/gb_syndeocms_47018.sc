if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103127" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-03-25 13:20:06 +0100 (Fri, 25 Mar 2011)" );
	script_bugtraq_id( 47018 );
	script_name( "SyndeoCMS Multiple Cross Site Scripting and SQL Injection Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/47018" );
	script_xref( name: "URL", value: "http://www.syndeocms.org/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/517160" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/517172" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/517162" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_SyndeoCMS_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "syndeocms/detected" );
	script_tag( name: "summary", value: "SyndeoCMS is prone to multiple cross-site scripting vulnerabilities
  and an SQL-injection vulnerability because it fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to steal cookie-
  based authentication credentials, compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "SyndeoCMS 2.8.02 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!dir = get_dir_from_kb( port: port, app: "syndeocms" )){
	exit( 0 );
}
url = NASLString( dir, "/starnet/addons/scroll_page.php?speed=--></script></head><script>alert('vt-xss-test');</script>" );
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('vt-xss-test'\\);</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

