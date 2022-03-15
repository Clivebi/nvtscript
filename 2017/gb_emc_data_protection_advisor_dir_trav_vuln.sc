CPE = "cpe:/a:dell:emc_data_protection_advisor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106549" );
	script_version( "2021-09-16T08:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 08:01:42 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-30 10:52:02 +0700 (Mon, 30 Jan 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-23 18:21:00 +0000 (Thu, 23 Jan 2020)" );
	script_cve_id( "CVE-2016-8211" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "EMC Data Protection Advisor Directory Traversal Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_emc_data_protection_advisor_detect.sc" );
	script_mandatory_keys( "emc_data_protection_advisor/installed" );
	script_tag( name: "summary", value: "EMC Data Protection Advisor is prone to a directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "EMC Data Protection Advisor is affected by a path traversal vulnerability.
  Attackers may potentially exploit this vulnerability to access unauthorized information by supplying specially
  crafted strings in input parameters of the application." );
	script_tag( name: "affected", value: "EMC Data Protection Advisor 6.1.x, 6.2, 6.2.1, 6.2.2 and 6.2.3 before patch 446." );
	script_tag( name: "solution", value: "Update to 6.2.3 patch 446 or later versions." );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2017/Jan/87" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "6.2.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.2.3 patch 446" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version == "6.2.3"){
	build = get_kb_item( "emc_data_protection_advisor/build" );
	if(!build || version_is_less( version: build, test_version: "446" )){
		report = report_fixed_ver( installed_version: version, installed_build: build, fixed_version: "6.2.3", fixed_build: "446" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

