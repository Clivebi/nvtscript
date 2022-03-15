CPE = "cpe:/a:oscommerce:oscommerce";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100099" );
	script_version( "2021-07-20T10:07:38+0000" );
	script_tag( name: "last_modification", value: "2021-07-20 10:07:38 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2009-04-05 13:52:05 +0200 (Sun, 05 Apr 2009)" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "osCommerce 'oscid' Session Fixation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_oscommerce_http_detect.sc" );
	script_mandatory_keys( "oscommerce/http/detected" );
	script_require_ports( "Services/www", 443 );
	script_tag( name: "summary", value: "osCommerce is prone to a session-fixation vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to hijack a user's session and gain
  unauthorized access to the affected application." );
	script_tag( name: "affected", value: "osCommerce 2.2 and 3.0 Beta. Other versions may also be affected." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34348" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/index.php?osCsid=a815a815a815a815";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!buf){
	exit( 0 );
}
if(egrep( pattern: "[a-zA-Z]+\\.php\\?osCsid=a815a815a815a815", string: buf ) && !egrep( pattern: "Set-Cookie: osCsid=[a-zA-Z0-9]+", string: buf )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

