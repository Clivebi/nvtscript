CPE = "cpe:/a:apache:tapestry";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145997" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-05-21 06:14:30 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-28 10:15:00 +0000 (Fri, 28 May 2021)" );
	script_cve_id( "CVE-2021-30638" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache Tapestry 5.4.0 < 5.6.4, 5.7.0 < 5.7.1 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_tapestry_http_detect.sc" );
	script_mandatory_keys( "apache/tapestry/detected" );
	script_tag( name: "summary", value: "Apache Tapestry is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An information exposure vulnerability in the context asset handling of
  Apache Tapestry allows an attacker to download files inside WEB-INF if using a
  specially-constructed URL. This was caused by an incomplete fix for CVE-2020-13953." );
	script_tag( name: "affected", value: "Apache Tapestry version 5.4.0 through 5.6.3 and 5.7.0 through 5.7.1." );
	script_tag( name: "solution", value: "Update to version 5.6.4, 5.7.2 or later." );
	script_xref( name: "URL", value: "https://www.openwall.com/lists/oss-security/2021/04/27/3" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "5.4.0", test_version2: "5.6.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.6.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.7.0", test_version2: "5.7.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.7.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

