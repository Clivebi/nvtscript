CPE = "cpe:/h:planex:ip_camera";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813883" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_cve_id( "CVE-2017-12574" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-21 16:23:00 +0000 (Wed, 21 Nov 2018)" );
	script_tag( name: "creation_date", value: "2018-09-03 15:43:26 +0530 (Mon, 03 Sep 2018)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "PLANEX CS-W50HD Hardcode Credential Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with PLANEX CS-W50HD
  network camera and is prone to hardcode credential vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to bypass authentication or not." );
	script_tag( name: "insight", value: "The flaw exists due to hardcoded credential
  'supervisor:dangerous' which are injected into web authentication database
  '/.htpasswd' during booting process." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain unauthorized access and control the device completely,
  the account can't be modified or deleted." );
	script_tag( name: "affected", value: "PLANEX CS-W50HD devices with firmware before 030720" );
	script_tag( name: "solution", value: "Upgrade to firmware version 030720 or
  later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2018/Aug/25" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_planex_csw50hd_camera_remote_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "planex/csw50hd/installed" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
auth = "Basic " + base64( str: "supervisor:dangerous" );
req = http_get_req( port: port, url: dir + "cgi-bin/info.cgi", add_headers: make_array( "Authorization", auth ) );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "IP CAM Information" ) && ContainsString( res, "CS-W50HD" ) && ContainsString( res, "WiFi Mac Address" ) && ContainsString( res, "Network type" ) && ContainsString( res, "IP CAM ID" )){
	report = "It was possible to login into the Web management UI at " + http_report_vuln_url( port: port, url: "/cgi-bin/info.cgi", url_only: TRUE ) + " using supervisor:dangerous as credentials.\r\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

