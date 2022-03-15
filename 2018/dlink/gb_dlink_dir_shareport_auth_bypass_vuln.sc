if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113146" );
	script_version( "2021-05-26T06:00:13+0200" );
	script_tag( name: "last_modification", value: "2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-03-29 09:53:55 +0200 (Thu, 29 Mar 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-23 15:48:00 +0000 (Fri, 23 Apr 2021)" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_cve_id( "CVE-2018-9032" );
	script_name( "D-Link DIR Routers SharePort Authentication Bypass Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dir_detect.sc" );
	script_require_ports( "Services/www", 80, 8080, 8181 );
	script_mandatory_keys( "Host/is_dlink_dir_device" );
	script_tag( name: "summary", value: "D-Link DIR Routers are prone to Authentication Bypass Vulnerability." );
	script_tag( name: "vuldetect", value: "The script tries to access protected information without authentication." );
	script_tag( name: "insight", value: "The directories '/category_view.php' and '/folder_view.php' can be accessed directly without authentication." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to access information about the target system
  that would normally require authentication." );
	script_tag( name: "affected", value: "D-Link DIR Routers with SharePort functionality. Firmware versions through 2.06." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove
  the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://www.youtube.com/watch?v=Wmm4p8znS3s" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/44378" );
	exit( 0 );
}
CPE_PREFIX = "cpe:/o:d-link";
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
port = infos["port"];
CPE = infos["cpe"];
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
for vuln_file in make_list( "/folder_view.php",
	 "/category_view.php" ) {
	url = dir + vuln_file;
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( res, "<title>SharePort Web Access</title>" ) && IsMatchRegexp( res, "href=\"webfile_css/layout.css\"" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

