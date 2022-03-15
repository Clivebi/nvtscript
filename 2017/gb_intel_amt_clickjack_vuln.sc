CPE = "cpe:/h:intel:active_management_technology";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106877" );
	script_version( "2021-09-13T12:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 12:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-16 13:48:56 +0700 (Fri, 16 Jun 2017)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-27 17:32:00 +0000 (Tue, 27 Jun 2017)" );
	script_cve_id( "CVE-2017-5697" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Intel Active Management Technology Clickjacking Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_intel_amt_webui_detect.sc" );
	script_mandatory_keys( "intel_amt/installed" );
	script_tag( name: "summary", value: "Insufficient clickjacking protection in the Web User Interface of Intel AMT
  firmware potentially allows a remote attacker to hijack users web clicks via attacker's crafted web page." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Intel AMT firmware versions before 9.1.40.1000, 9.5.60.1952, 10.0.50.1004,
  11.0.0.1205, and 11.6.25.1129." );
	script_tag( name: "solution", value: "Update firmware to version 9.1.40.1000, 9.5.60.1952, 10.0.50.1004,
  11.0.0.1205, 11.6.25.1129 or later." );
	script_xref( name: "URL", value: "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00081.html" );
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
if(version_is_less( version: version, test_version: "9.1.40.1000" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.1.40.1000" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^9\\.5\\." )){
	if(version_is_less( version: version, test_version: "9.5.60.1952" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.5.60.1952" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^10\\.0\\." )){
	if(version_is_less( version: version, test_version: "10.0.50.1004" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "10.0.50.1004" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^11\\.6\\." )){
	if(version_is_less( version: version, test_version: "11.6.25.1129" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "11.6.25.1129" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

