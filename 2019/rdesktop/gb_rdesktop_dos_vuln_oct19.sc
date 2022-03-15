if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113554" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-11-04 11:01:11 +0000 (Mon, 04 Nov 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-04 18:11:00 +0000 (Mon, 04 Nov 2019)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2019-15682" );
	script_name( "rdesktop <= 1.8.4 Denial of Service (DoS) vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_rdesktop_detect_lin.sc" );
	script_mandatory_keys( "rdesktop/detected" );
	script_tag( name: "summary", value: "rdesktop is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists because of multiple
  out-of-bound access reads in the code." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to crash the application." );
	script_tag( name: "affected", value: "rdesktop through version 1.8.4." );
	script_tag( name: "solution", value: "Update to version 1.8.5." );
	script_xref( name: "URL", value: "https://ics-cert.kaspersky.com/advisories/klcert-advisories/2019/10/30/klcert-19-032-denial-of-service-in-rdesktop-before-1-8-4/" );
	exit( 0 );
}
CPE = "cpe:/a:rdesktop:rdesktop";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "1.8.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.8.5", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

