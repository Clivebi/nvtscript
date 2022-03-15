if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17636" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_cve_id( "CVE-2005-0420" );
	script_bugtraq_id( 12459 );
	script_name( "Outlook Web Access URL Injection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michael J. Richardson" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/36079/Exploit-Labs-Security-Advisory-2005.1.html" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "Due to a lack of sanitization of the user input, the remote version of Microsoft
  Outlook Web Access 2003 is vulnerable to URL injection which can be exploited to redirect a user to a different,
  unauthorized web server after authenticating to OWA." );
	script_tag( name: "impact", value: "This unauthorized site could be used to capture sensitive information by
  appearing to be part of the web application." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
url = "/exchweb/bin/auth/owalogon.asp?url=http://12345678910";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!res){
	exit( 0 );
}
if(ereg( pattern: "^HTTP/1\\.[01] 200 ", string: res ) && ContainsString( res, "owaauth.dll" ) && ContainsString( res, "<INPUT type=\"hidden\" name=\"destination\" value=\"http://12345678910\">" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

