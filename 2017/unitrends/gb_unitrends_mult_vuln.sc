CPE = "cpe:/a:unitrends:backup";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140447" );
	script_version( "2021-09-09T13:03:05+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 13:03:05 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-23 15:52:55 +0700 (Mon, 23 Oct 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-10-26 01:29:00 +0000 (Thu, 26 Oct 2017)" );
	script_cve_id( "CVE-2017-12477", "CVE-2017-12478", "CVE-2017-12479" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Unitrends < 10.0.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_unitrends_http_detect.sc" );
	script_mandatory_keys( "unitrends/detected" );
	script_tag( name: "summary", value: "Unitrends UEB is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "Unitrends UEB is prone to multiple vulnerabilities:

  - Unauthenticated root RCE (CVE-2017-12477, CVE-2017-12478)

  - Authenticated lowpriv RCE (CVE-2017-12479)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Unitrends UEB prior to version 10.0.0" );
	script_tag( name: "solution", value: "Update to version 10.0.0 or later." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/42957/" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/42958/" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/42959/" );
	script_xref( name: "URL", value: "https://support.unitrends.com/UnitrendsBackup/s/article/000005755" );
	script_xref( name: "URL", value: "https://support.unitrends.com/UnitrendsBackup/s/article/000005756" );
	script_xref( name: "URL", value: "https://support.unitrends.com/UnitrendsBackup/s/article/000005757" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "10.0.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.0.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

