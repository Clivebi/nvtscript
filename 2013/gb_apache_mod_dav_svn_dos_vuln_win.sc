CPE = "cpe:/a:apache:http_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803743" );
	script_version( "2021-03-01T08:21:56+0000" );
	script_cve_id( "CVE-2013-1896" );
	script_bugtraq_id( 61129 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-03-01 08:21:56 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2013-08-21 18:57:17 +0530 (Wed, 21 Aug 2013)" );
	script_name( "Apache HTTP Server 'mod_dav_svn' Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "Apache HTTP Server is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to Apache HTTP Server 2.2.25 or later." );
	script_tag( name: "insight", value: "The flaw is due to an error in 'mod_dav.c', It does not properly determine
  whether DAV is enabled for a URI." );
	script_tag( name: "affected", value: "Apache HTTP Server version before 2.2.25." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to cause a denial of
  service (segmentation fault) via a MERGE request in which the URI is
  configured for handling by the mod_dav_svn module." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.apache.org/dist/httpd/Announcement2.2.html" );
	script_xref( name: "URL", value: "http://svn.apache.org/viewvc/httpd/httpd/trunk/modules/dav/main/mod_dav.c?view=log" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_http_server_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/http_server/detected", "Host/runs_windows" );
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
if(version_is_less( version: vers, test_version: "2.2.25" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.2.25", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

