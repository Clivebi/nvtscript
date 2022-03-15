CPE = "cpe:/a:apple:itunes";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811879" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_cve_id( "CVE-2017-7081", "CVE-2017-7087", "CVE-2017-7091", "CVE-2017-7092", "CVE-2017-7093", "CVE-2017-7094", "CVE-2017-7095", "CVE-2017-7096", "CVE-2017-7098", "CVE-2017-7099", "CVE-2017-7100", "CVE-2017-7102", "CVE-2017-7104", "CVE-2017-7107", "CVE-2017-7111", "CVE-2017-7117", "CVE-2017-7120", "CVE-2017-7090", "CVE-2017-7109" );
	script_bugtraq_id( 100985, 100995, 100994, 101006, 100998, 100986, 101005 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-08 16:06:00 +0000 (Fri, 08 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-10-25 11:53:06 +0530 (Wed, 25 Oct 2017)" );
	script_name( "Apple iTunes Security Updates (HT208141)" );
	script_tag( name: "summary", value: "This host is installed with Apple iTunes
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple memory corruption issues.

  - A permissions issue existed in the handling of web browser cookies.

  - Application Cache policy may be unexpectedly applied." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attackers to execute arbitrary code
  and bypass security." );
	script_tag( name: "affected", value: "Apple iTunes versions before 12.7" );
	script_tag( name: "solution", value: "Upgrade to Apple iTunes 12.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT208141" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_itunes_detection_win_900123.sc" );
	script_mandatory_keys( "iTunes/Win/Installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!ituneVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ituneVer, test_version: "12.7.0.166" )){
	report = report_fixed_ver( installed_version: ituneVer, fixed_version: "12.7" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

