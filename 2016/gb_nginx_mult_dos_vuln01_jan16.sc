CPE = "cpe:/a:nginx:nginx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806849" );
	script_version( "2021-02-01T11:36:44+0000" );
	script_cve_id( "CVE-2016-0742", "CVE-2016-0746", "CVE-2016-0747" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-02-01 11:36:44 +0000 (Mon, 01 Feb 2021)" );
	script_tag( name: "creation_date", value: "2016-01-27 17:26:59 +0530 (Wed, 27 Jan 2016)" );
	script_name( "nginx Multiple Denial Of Service Vulnerabilities 01 - Jan16" );
	script_tag( name: "summary", value: "nginx is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist:

  - An invalid pointer dereference might occur during DNS server response processing.

  - The use-after-free condition might occur during CNAME response processing.

  - The CNAME resolution was insufficiently limited." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to trigger arbitrary name
  resolution to cause excessive resource consumption in worker processes, to forge UDP packets from the DNS
  server to cause worker process crash." );
	script_tag( name: "affected", value: "nginx versions from 0.6.18 to 1.9.9.

  Note: 1.8.1 is not vulnerable." );
	script_tag( name: "solution", value: "Update to nginx version 1.9.10 or 1.8.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://mailman.nginx.org/pipermail/nginx/2016-January/049700.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_nginx_consolidation.sc" );
	script_mandatory_keys( "nginx/detected" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(IsMatchRegexp( version, "^0\\." )){
	if(version_in_range( version: version, test_version: "0.6", test_version2: "0.8.55" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.9.10/1.8.1", install_path: location );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^1\\." )){
	if(version_is_less( version: version, test_version: "1.8.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.9.10/1.8.1", install_path: location );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^1\\.9" )){
	if(version_is_less( version: version, test_version: "1.9.10" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.9.10", install_path: location );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

