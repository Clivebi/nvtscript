CPE = "cpe:/a:atlassian:confluence";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806815" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_cve_id( "CVE-2015-8398", "CVE-2015-8399" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2016-01-08 16:21:20 +0530 (Fri, 08 Jan 2016)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "Atlassian Confluence XSS and Insecure Direct Object Reference Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Atlassian
  Confluence and is prone to cross site scripting and insecure direct object
  reference vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - An improper sanitization of user supplied input via different parameters
  in the REST API.

  - An Insecure Direct Object Reference via parameter 'decoratorName'." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session
  and to read configuration files from the application." );
	script_tag( name: "affected", value: "Confluence versions 5.9.1, 5.8.14
  5.8.15, 5.2." );
	script_tag( name: "solution", value: "Upgrade to Confluence version 5.8.17 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/39170/" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2016/Jan/5" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/135130/confluence-xssdisclose.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_atlassian_confluence_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "atlassian/confluence/detected" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/rest/prototype/1/session/check/something%3Cimg%20src%3da%20onerror%3dalert%28document.cookie%29%3E";
if(http_vuln_check( port: port, url: url, pattern: "alert\\(document.cookie\\)", check_header: TRUE, extra_check: "Expected user" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

