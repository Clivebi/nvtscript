CPE = "cpe:/a:jenkins:jenkins";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108591" );
	script_version( "2021-08-31T08:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-06-03 12:16:09 +0000 (Mon, 03 Jun 2019)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-08 22:23:00 +0000 (Wed, 08 May 2019)" );
	script_cve_id( "CVE-2018-1000861" );
	script_bugtraq_id( 106176 );
	script_name( "Jenkins < 2.121.3 / < 2.138 ACL Bypass Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_jenkins_consolidation.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "jenkins/detected" );
	script_tag( name: "summary", value: "Jenkins is prone to an ACL bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Tries to bypass the ACL policy of Jenkins via a crafted HTTP GET request." );
	script_tag( name: "impact", value: "By prepending '/securityRealm/user/admin' to specific URLs an attacker is able to
  bypass the ACL configuration of Jenkins and to access restricted areas on the remote application." );
	script_tag( name: "affected", value: "Jenkins weekly up to and including 2.137, Jenkins LTS up to and including 2.121.2." );
	script_tag( name: "solution", value: "Upgrade Jenkins weekly to 2.138 or later / Jenkins LTS to 2.121.3 or later." );
	script_xref( name: "URL", value: "https://jenkins.io/security/advisory/2018-08-15/" );
	script_xref( name: "URL", value: "https://blog.orange.tw/2019/01/hacking-jenkins-part-1-play-with-dynamic-routing.html" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(get_kb_item( "jenkins/" + port + "/" + dir + "/anonymous_read_enabled" )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
base_url = "/search/index?q=a";
check_url = dir + base_url;
req = http_get( port: port, item: check_url );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!buf || IsMatchRegexp( buf, "^HTTP/[0-9]([.][0-9]+)? 200" ) || !IsMatchRegexp( buf, "^HTTP/[0-9]([.][0-9]+)? 403" ) || ContainsString( buf, "<title>Search for" )){
	exit( 0 );
}
bypass_url = dir + "/securityRealm/user/admin" + base_url;
req = http_get( port: port, item: bypass_url );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(buf && IsMatchRegexp( buf, "^HTTP/[0-9]([.][0-9]+)? " ) && ( ContainsString( buf, "<title>Search for 'a'" ) || ContainsString( buf, ">Nothing seems to match.<" ) )){
	report = "By accessing \"" + http_report_vuln_url( port: port, url: check_url, url_only: TRUE ) + "\" it was possible to verify that the page is protected via an ACL policy.\n";
	report += "By accessing \"" + http_report_vuln_url( port: port, url: bypass_url, url_only: TRUE ) + "\" it was possible to circumvent this protection and run a search on the target host.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

