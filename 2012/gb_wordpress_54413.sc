CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103516" );
	script_bugtraq_id( 54413 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_name( "WordPress Global Content Blocks PHP Code Execution and Information Disclosure Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54413" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/49854" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2012-07-13 11:23:37 +0200 (Fri, 13 Jul 2012)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Global Content Blocks is prone to multiple security vulnerabilities,
  including a remote PHP code-execution vulnerability and multiple information-
  disclosure vulnerability." );
	script_tag( name: "impact", value: "Successful exploits of these issues may allow remote attackers to
  execute arbitrary malicious PHP code in the context of the application
  or obtain potentially sensitive information." );
	script_tag( name: "affected", value: "Global Content Blocks 1.5.1 is vulnerable, other versions may also
  be affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = dir + "/wp-content/plugins/global-content-blocks/resources/tinymce/gcb_ajax_add.php";
vtstrings = get_vt_strings();
check = vtstrings["lowercase"] + "_test";
host = http_host_name( port: port );
ex = "name=" + check + "&content=" + check + "&description=vt_test&type=php";
len = strlen( ex );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length:", len, "\\r\\n", "\\r\\n", ex );
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( result, check ) && !ContainsString( result, "php.png" )){
	exit( 0 );
}
id = eregmatch( pattern: "\"id\":([0-9]+)", string: result );
if(isnull( id[1] )){
	exit( 0 );
}
url = dir + "/wp-content/plugins/global-content-blocks/gcb/gcb_export.php?gcb=" + id[1];
if(http_vuln_check( port: port, url: url, pattern: "b3BlbnZhc190ZXN0" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

