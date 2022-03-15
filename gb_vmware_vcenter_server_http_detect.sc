if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103659" );
	script_version( "2021-09-28T06:32:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-28 06:32:28 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2013-02-06 17:30:38 +0100 (Wed, 06 Feb 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "VMware vCenter Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of VMware vCenter Server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
host = http_host_name( port: port );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = NASLString( "GET / HTTP/1.1\\r\\n" );
req += NASLString( "Host: ", host, "\\r\\n\\r\\n" );
send( socket: soc, data: req );
buf = recv( socket: soc, length: 8192 );
close( soc );
if(!buf || !ContainsString( buf, "VMware" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
version = "unknown";
build = "unknown";
url = "/sdk";
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n" );
req += NASLString( "Host: ", host, "\\r\\n" );
req += NASLString( "Content-Type: application/x-www-form-urlencoded\\r\\n" );
req += NASLString( "Content-Length: 348\\r\\n\\r\\n" );
req += NASLString( "
<env:Envelope xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:env=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">
\t\t\t<env:Body>
\t\t\t<RetrieveServiceContent xmlns=\"urn:vim25\">
\t\t\t\t<_this type=\"ServiceInstance\">ServiceInstance</_this>
\t\t\t</RetrieveServiceContent>
\t\t\t</env:Body>
</env:Envelope>" );
req += NASLString( "\\r\\n" );
send( socket: soc, data: req );
buf = recv( socket: soc, length: 8192 );
close( soc );
if(!buf || !ContainsString( buf, "RetrieveServiceContentResponse" ) || !ContainsString( buf, "<fullName>VMware vCenter Server" )){
	exit( 0 );
}
set_kb_item( name: "vmware/vcenter/server/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
vers = eregmatch( pattern: "<version>([0-9.]+)</version>", string: buf );
if(!isnull( vers[1] )){
	version = vers[1];
}
bld = eregmatch( pattern: "<build>([0-9]+)</build>", string: buf );
if(!isnull( bld[1] )){
	build = bld[1];
}
r = eregmatch( pattern: "<returnval>(.*)</returnval>", string: buf );
if(!isnull( r[1] )){
	set_kb_item( name: "vmware/vcenter/server/http/" + port + "/concluded", value: r[1] );
}
set_kb_item( name: "vmware/vcenter/server/detected", value: TRUE );
set_kb_item( name: "vmware/vcenter/server/http/detected", value: TRUE );
set_kb_item( name: "vmware/vcenter/server/http/port", value: port );
set_kb_item( name: "vmware/vcenter/server/http/" + port + "/version", value: version );
set_kb_item( name: "vmware/vcenter/server/http/" + port + "/build", value: build );
set_kb_item( name: "www/action_jsp_do", value: TRUE );
exit( 0 );

