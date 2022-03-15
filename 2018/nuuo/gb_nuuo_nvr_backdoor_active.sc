CPE = "cpe:/a:nuuo:nuuo";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141487" );
	script_version( "2021-05-28T06:00:18+0200" );
	script_tag( name: "last_modification", value: "2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2018-09-18 10:28:22 +0700 (Tue, 18 Sep 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2018-1150" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "NUUO NVR < 3.9.1 Backdoor Activated" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nuuo_devices_web_detect.sc" );
	script_mandatory_keys( "nuuo/web/detected" );
	script_tag( name: "summary", value: "The Backdoor in NUUO NVR is active." );
	script_tag( name: "insight", value: "If the file '/tmp/moses' is present on the device unauthenticated remote
attacker can list all of the non-admin users and change their passwords" );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks if the backdoor is active." );
	script_tag( name: "solution", value: "Update to version 3.9.1 (03.09.0001.0000) or later. Remove the file
'/tmp/moses' from the system. Recheck if malicious users have been added and change all passwords." );
	script_xref( name: "URL", value: "https://www.nuuo.com/NewsDetail.php?id=0425" );
	script_xref( name: "URL", value: "https://www.tenable.com/security/research/tra-2018-25" );
	script_xref( name: "URL", value: "https://www.tenable.com/blog/tenable-research-advisory-peekaboo-critical-vulnerability-in-nuuo-network-video-recorder" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port, nofork: TRUE )){
	exit( 0 );
}
url = "/users_xml.php";
if(http_vuln_check( port: port, url: url, pattern: "<AccountInfo>", check_header: TRUE )){
	report = "The backdoor seems to be activated since an unauthenticated request to " + http_report_vuln_url( port: port, url: url, url_only: TRUE ) + " returns information about all non-admin" + " users.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

