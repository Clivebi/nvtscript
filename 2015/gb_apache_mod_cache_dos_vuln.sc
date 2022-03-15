CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805634" );
	script_version( "2021-03-01T08:21:56+0000" );
	script_cve_id( "CVE-2013-4352" );
	script_bugtraq_id( 68863, 69248 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-03-01 08:21:56 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2015-05-27 12:15:46 +0530 (Wed, 27 May 2015)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Apache HTTP Server 'mod_cache' Denial of Service Vulnerability May15" );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to vulnerability in
  'cache_invalidate' function in modules/cache/cache_storage.c script in the
   mod_cache module in the Apache HTTP Server." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to cause a denial of service via specially crafted request." );
	script_tag( name: "affected", value: "Apache HTTP Server version 2.4.6." );
	script_tag( name: "solution", value: "Update to version 2.4.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=1120604" );
	script_xref( name: "URL", value: "http://httpd.apache.org/security/vulnerabilities_24.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc" );
	script_mandatory_keys( "apache/http_server/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_equal( version: vers, test_version: "2.4.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.4.7", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

