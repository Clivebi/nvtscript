CPE = "cpe:/a:djangoproject:django";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145922" );
	script_version( "2021-08-26T14:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-05-07 07:00:40 +0000 (Fri, 07 May 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-11 11:15:00 +0000 (Fri, 11 Jun 2021)" );
	script_cve_id( "CVE-2021-32052" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Django 2.2 < 2.2.22, 3.1 < 3.1.10, 3.2 < 3.2.2 Header Injection Vulnerability - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_django_detect_lin.sc" );
	script_mandatory_keys( "Django/Linux/Ver" );
	script_tag( name: "summary", value: "Django is prone to a header injection vulnerability." );
	script_tag( name: "insight", value: "On Python 3.9.5+, URLValidator didn't prohibit newlines and tabs.
  If you used values with newlines in HTTP response, you could suffer from header injection attacks.
  Django itself wasn't vulnerable because HttpResponse prohibits newlines in HTTP headers.

  Moreover, the URLField form field which uses URLValidator silently removes newlines and tabs on
  Python 3.9.5+, so the possibility of newlines entering your data only existed if you are using
  this validator outside of the form fields." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Django 2.2 before 2.2.22, 3.1 before 3.1.10, and 3.2 before 3.2.2" );
	script_tag( name: "solution", value: "Update to version 2.2.22, 3.1.10, 3.2.2 or later." );
	script_xref( name: "URL", value: "https://www.djangoproject.com/weblog/2021/may/06/security-releases/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "2.2.0", test_version2: "2.2.21" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.2.22", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.1.0", test_version2: "3.1.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.1.10", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.2.0", test_version2: "3.2.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.2.2", install_path: location );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

