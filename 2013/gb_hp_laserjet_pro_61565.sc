CPE_PREFIX = "cpe:/h:hp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103757" );
	script_bugtraq_id( 61565 );
	script_cve_id( "CVE-2013-4807" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:C/A:N" );
	script_version( "2020-12-07T13:33:44+0000" );
	script_name( "Multiple HP LaserJet Pro Printers Unspecified Information Disclosure Vulnerability" );
	script_tag( name: "last_modification", value: "2020-12-07 13:33:44 +0000 (Mon, 07 Dec 2020)" );
	script_tag( name: "creation_date", value: "2013-08-12 16:59:44 +0200 (Mon, 12 Aug 2013)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_hp_printer_detect.sc" );
	script_mandatory_keys( "hp_printer/installed" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/61565" );
	script_tag( name: "impact", value: "The vulnerability could be exploited remotely to gain unauthorized access to data." );
	script_tag( name: "vuldetect", value: "Request /dev/save_restore.xml and read the response." );
	script_tag( name: "insight", value: "The hidden URL '/dev/save_restore.xml' contains a hex representation
  of the admin password in plaintext and no authentication is needed to access this site." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "summary", value: "Multiple HP LaserJet Pro Printers are prone to an information-disclosure
  vulnerability." );
	script_tag( name: "affected", value: "HP LaserJet Pro P1102w

  HP LaserJet Pro P1606dn

  HP LaserJet Pro M1212nf MFP

  HP LaserJet Pro M1213nf MFP

  HP LaserJet Pro M1214nfh MFP

  HP LaserJet Pro M1216nfh MFP

  HP LaserJet Pro M1217nfw MFP

  HP LaserJet Pro M1218nfs MFP

  HP LaserJet Pro CP1025nw" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
cpe = infos["cpe"];
if(!ContainsString( cpe, "laserjet" )){
	exit( 99 );
}
port = infos["port"];
if(!get_app_location( cpe: cpe, port: port )){
	exit( 0 );
}
url = "/dev/save_restore.xml";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req );
if(ContainsString( buf, "<name>e_HttpPassword</name>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

