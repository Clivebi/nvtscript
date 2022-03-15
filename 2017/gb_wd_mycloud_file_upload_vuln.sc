CPE_PREFIX = "cpe:/o:wdc";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140610" );
	script_version( "2021-09-10T10:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-19 09:48:55 +0700 (Tue, 19 Dec 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-28 15:08:00 +0000 (Tue, 28 May 2019)" );
	script_cve_id( "CVE-2017-17560" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Western Digital My Cloud File Upload Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wd_mycloud_consolidation.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wd-mycloud/http/detected" );
	script_tag( name: "summary", value: "Western Digital My Cloud is prone to a file upload vulnerability." );
	script_tag( name: "insight", value: "The /web/jquery/uploader/multi_uploadify.php PHP script provides multipart
  upload functionality that is accessible without authentication and can be used to place a file anywhere on the
  device's file system. This allows an attacker the ability to upload a PHP shell onto the device and obtain
  arbitrary code execution as root." );
	script_tag( name: "impact", value: "Successful exploit allows an attacker to execute arbitrary commands with
  root privileges in context of the affected application." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "solution", value: "The vendor has released firmware updates. Please see the reference for
  more details and downloads." );
	script_xref( name: "URL", value: "http://gulftech.org/advisories/WDMyCloud%20Multiple%20Vulnerabilities/125" );
	script_xref( name: "URL", value: "https://www.exploitee.rs/index.php/Western_Digital_MyCloud" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/43356/" );
	script_xref( name: "URL", value: "http://support.wdc.com/downloads.aspx?lang=en#firmware" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" )){
	exit( 0 );
}
CPE = infos["cpe"];
if(!CPE || !ContainsString( CPE, "my_cloud" )){
	exit( 0 );
}
port = infos["port"];
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/web/jquery/uploader/multi_uploadify.php";
req = http_get_req( port: port, url: url, host_header_use_ip: TRUE );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 302" ) && ContainsString( res, "Location: ?status=1" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

