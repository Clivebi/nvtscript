if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113535" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-09-30 11:55:55 +0200 (Mon, 30 Sep 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-23 17:20:00 +0000 (Fri, 23 Apr 2021)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_cve_id( "CVE-2019-16190" );
	script_name( "D-Link DIR devices Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dsl_detect.sc", "gb_dlink_dap_detect.sc", "gb_dlink_dir_detect.sc", "gb_dlink_dwr_detect.sc" );
	script_mandatory_keys( "Host/is_dlink_device" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "Multiple D-Link DIR devices are prone to an authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Tries to access sensitive pages without authentication." );
	script_tag( name: "insight", value: "The SharePort Web Access on D-Link DIR devices allows authentication bypass
  through a direct request to folder_view.php or category_view.php." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to access sensitive data
  or execute php code contained in files on the target machine." );
	script_tag( name: "affected", value: "The following devices and firmwares are affected:

  - D-Link DIR-868L REVB through version 2.03

  - D-Link DIR-885L REVA through version 1.20

  - D-Link DIR-895L REVA through version 1.21

  Other devices and firmware versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://cyberloginit.com/2019/09/10/dlink-shareport-web-access-authentication-bypass.html" );
	exit( 0 );
}
CPE_PREFIX = "cpe:/o:d-link";
require("host_details.inc.sc");
require("misc_func.inc.sc");
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
path_list = make_list( "/folder_view.php",
	 "/category_view.php",
	 "/webaccess/folder_view.php",
	 "/webaccess/category_view.php" );
for path in path_list {
	url = dir + path;
	buf = http_get_cache( port: port, item: url );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( IsMatchRegexp( buf, "alert\\(\"No HardDrive Connected\"\\);" ) || IsMatchRegexp( buf, "location.href='doc.php" ) )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

