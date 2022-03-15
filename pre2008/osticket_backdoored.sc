CPE = "cpe:/a:osticket:osticket";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12649" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "osTicket Backdoored" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "osticket_detect.sc" );
	script_mandatory_keys( "osticket/installed" );
	script_tag( name: "solution", value: "1) Remove any PHP files from the /attachments/ directory.

  2) Place an index.html file there to prevent directory listing of that directory.

  3) Upgrade osTicket to the latest version." );
	script_tag( name: "summary", value: "There is a vulnerability in the current version of osTicket
  that allows an attacker to upload an PHP script, and then access it causing it to execute.

  This script tries to detect infected servers." );
	script_tag( name: "impact", value: "This attack is being actively exploited by attackers to take over
  servers." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
req = http_get( item: dir + "/attachments/", port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(isnull( res ) || !ContainsString( res, "[DIR]" )){
	exit( 0 );
}
v = eregmatch( pattern: "<A HREF=\"([^\"]+.php)\">", string: res );
if(isnull( v )){
	exit( 0 );
}
url = dir + "/attachments/" + v[1];
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(isnull( res )){
	exit( 0 );
}
if(ContainsString( res, "PHP Shell" ) || ContainsString( res, "<input type = 'text' name = 'cmd' value = '' size = '75'>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

