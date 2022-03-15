if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804775" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2014-3080", "CVE-2014-3081", "CVE-2014-3085" );
	script_bugtraq_id( 68777, 68779, 68939 );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-10-13 16:48:44 +0530 (Mon, 13 Oct 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "IBM Global Console Manager switches Multiple XSS Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with IBM Global
  Console Manager switches and is prone to multiple xss vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Flaw is due to improper sanitization of
  user-supplied input passed via 'query' parameter to kvm.cgi and 'key'
  parameter to avctalert.php script." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site." );
	script_tag( name: "affected", value: "IBM GCM16 and GCM32 Global Console Manager
  switches with firmware before 1.20.20.23447" );
	script_tag( name: "solution", value: "Update to firmware version 1.20.20.23447 or newer." );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/34132" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2014/Jul/113" );
	script_xref( name: "URL", value: "http://www.ibm.com/support/entry/portal/docdisplay?lndocid=migr-5095983" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
http_port = http_get_port( default: 443 );
rcvRes = http_get_cache( item: "/login.php", port: http_port );
if(ContainsString( rcvRes, ">GCM" )){
	url = "/avctalert.php?key=<script>alert(document.cookie)</script>";
	sndReq = http_get( item: url, port: http_port );
	rcvRes = http_keepalive_send_recv( port: http_port, data: sndReq );
	if(IsMatchRegexp( rcvRes, "HTTP/1\\.. 200" ) && ContainsString( rcvRes, "<script>alert(document.cookie)</script>" )){
		security_message( port: http_port );
		exit( 0 );
	}
}
exit( 99 );

