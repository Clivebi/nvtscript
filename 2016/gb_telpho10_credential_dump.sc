CPE = "cpe:/a:telpho:telpho10";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140076" );
	script_version( "2020-05-11T10:14:42+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-05-11 10:14:42 +0000 (Mon, 11 May 2020)" );
	script_tag( name: "creation_date", value: "2016-11-21 13:35:52 +0100 (Mon, 21 Nov 2016)" );
	script_name( "Telpho10 Credentials Disclosure Vulnerability" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_telpho10_web_interface_detect.sc" );
	script_mandatory_keys( "telpho10/webinterface/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "It is possible to create and read a configuration backup of Telpho10.
  This backup contains the credentials for admin login." );
	script_tag( name: "vuldetect", value: "Try to generate and read a configuration backup." );
	script_tag( name: "affected", value: "Telpho10 <= 2.6.31." );
	script_tag( name: "solution", value: "Upgrade to version 2.6.32 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( port: port, cpe: CPE )){
	exit( 0 );
}
url = "/telpho/system/backup.php";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req );
if(!buf || !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" )){
	exit( 0 );
}
url1 = "/telpho/temp/telpho10.epb";
req = http_get( item: url1, port: port );
buf = http_send_recv( port: port, data: req );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "control.tar" ) && ContainsString( buf, "ustar" )){
	report = "By requesting " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " it was possible to generate a backup of the device.\nThis backup could be retrieved by requesting " + http_report_vuln_url( port: port, url: url1, url_only: TRUE ) + ".";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

