CPE = "cpe:/a:hp:system_management_homepage";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106390" );
	script_version( "2021-09-20T14:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 14:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-11-15 10:22:35 +0700 (Tue, 15 Nov 2016)" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_cve_id( "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2109", "CVE-2016-3739", "CVE-2016-4070", "CVE-2016-4071", "CVE-2016-4072", "CVE-2016-4342", "CVE-2016-4343", "CVE-2016-4393", "CVE-2016-4394", "CVE-2016-4395", "CVE-2016-4396", "CVE-2016-4537", "CVE-2016-4538", "CVE-2016-4539", "CVE-2016-4540", "CVE-2016-4541", "CVE-2016-4542", "CVE-2016-4543", "CVE-2016-5385", "CVE-2016-5387", "CVE-2016-5388" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "HP System Management Homepage Multiple Vulnerabilities (Oct-2016)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_hp_smh_detect.sc" );
	script_mandatory_keys( "HP/SMH/installed" );
	script_tag( name: "summary", value: "HP System Management Homepage is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple potential security vulnerabilities have been identified in HPE
System Management Homepage (SMH) on Windows and Linux." );
	script_tag( name: "impact", value: "The vulnerabilities could be remotely exploited using man-in-the-middle
(MITM) attacks resulting in cross-site scripting (XSS), arbitrary code execution, Denial of Service (DoS),
and/or unauthorized disclosure of information." );
	script_tag( name: "affected", value: "HPE System Management Homepage all versions prior to v7.6" );
	script_tag( name: "solution", value: "Update to v7.6.0 or later" );
	script_xref( name: "URL", value: "https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05320149" );
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
if(version_is_less( version: version, test_version: "7.6.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.6.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

