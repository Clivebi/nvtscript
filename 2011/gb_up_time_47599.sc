if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103148" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)" );
	script_bugtraq_id( 47599 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "up.time Software Administration Interface Remote Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/47599" );
	script_xref( name: "URL", value: "http://www.insomniasec.com/advisories/ISVA-110427.2.htm" );
	script_xref( name: "URL", value: "http://www.uptimesoftware.com/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_up_time_detect.sc" );
	script_require_ports( "Services/www", 9999 );
	script_mandatory_keys( "up.time/installed" );
	script_tag( name: "summary", value: "up.time software is prone to a remote authentication-bypass
  vulnerability." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to bypass authentication and perform
  unauthorized actions." );
	script_tag( name: "affected", value: "up.time 5 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 9999 );
if(!dir = get_dir_from_kb( port: port, app: "up.time" )){
	exit( 0 );
}
url = NASLString( dir, "/index.php?userid=admin&firstTimeLogin=True&password=&confirmPassword=&adminEmail=admin@admin&monitorEmail=admin@admin" );
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!buf){
	exit( 0 );
}
if(ContainsString( buf, "The password cannot be blank" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

