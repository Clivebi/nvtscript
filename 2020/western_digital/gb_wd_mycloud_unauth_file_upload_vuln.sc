CPE_PREFIX = "cpe:/o:wdc";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108955" );
	script_version( "2021-08-16T09:00:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-16 09:00:57 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-10-21 10:09:10 +0000 (Wed, 21 Oct 2020)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-28 18:29:00 +0000 (Tue, 28 May 2019)" );
	script_cve_id( "CVE-2019-9951" );
	script_name( "Western Digital My Cloud Unauthenticated File Upload Vulnerability (Active Check)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wd_mycloud_consolidation.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wd-mycloud/http/detected" );
	script_xref( name: "URL", value: "https://community.wd.com/t/new-release-my-cloud-firmware-versions-2-31-174-3-26-19/235932" );
	script_xref( name: "URL", value: "https://github.com/bnbdr/wd-rce/" );
	script_xref( name: "URL", value: "https://bnbdr.github.io/posts/wd/" );
	script_tag( name: "summary", value: "Western Digital My Cloud is prone to an unauthenticatedfile upload vulnerability." );
	script_tag( name: "insight", value: "The page web/jquery/uploader/uploadify.php can be accesses without any credentials
  and allows uploading arbitrary files to any location on the attached storage under either:

  - /mnt/HD

  - /mnt/USB

  - /mnt/isoMount" );
	script_tag( name: "impact", value: "Successful exploit allows an attacker to execute arbitrary commands with
  root privileges in context of the affected application." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks the response." );
	script_tag( name: "solution", value: "The vendor has released firmware updates. Please see the reference for
  more details and downloads." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
url = dir + "/web/jquery/uploader/uploadify.php";
req = http_get_req( port: port, url: url, host_header_use_ip: TRUE );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( res, "\\{\"success\":false\\}$" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

