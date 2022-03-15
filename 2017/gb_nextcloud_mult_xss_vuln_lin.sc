CPE = "cpe:/a:nextcloud:nextcloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811137" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_cve_id( "CVE-2017-0893", "CVE-2017-0891" );
	script_bugtraq_id( 98423, 98411 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-05-30 16:57:47 +0530 (Tue, 30 May 2017)" );
	script_name( "Nextcloud Multiple XSS Vulnerabilities (Linux)" );
	script_tag( name: "summary", value: "Nextcloud is prone to multiple XSS vulnerabilities" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An inadequate escaping of error message in multiple components.

  - Nextcloud Server shipping a vulnerable JavaScript library for sanitizing
    untrusted user-input." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to write or paste malicious content into the server." );
	script_tag( name: "affected", value: "Nextcloud Server 9.0.x before 9.0.58, 10.0.x
  before 10.0.5 and 11.0.x before 11.0.3 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Nextcloud Server 9.0.58, or 10.0.5,
  or 11.0.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://nextcloud.com/security/advisory/?id=nc-sa-2017-010" );
	script_xref( name: "URL", value: "https://nextcloud.com/security/advisory/?id=nc-sa-2017-008" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nextcloud_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "nextcloud/installed", "Host/runs_unixoide" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if( IsMatchRegexp( vers, "^11\\." ) && version_is_less( version: vers, test_version: "11.0.3" ) ){
	fix = "11.0.3";
}
else {
	if( IsMatchRegexp( vers, "^10\\." ) && version_is_less( version: vers, test_version: "10.0.5" ) ){
		fix = "10.0.5";
	}
	else {
		if(IsMatchRegexp( vers, "^9\\." ) && version_is_less( version: vers, test_version: "9.0.58" )){
			fix = "9.0.58";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

