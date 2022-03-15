CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112040" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-12 07:56:49 +0200 (Tue, 12 Sep 2017)" );
	script_cve_id( "CVE-2017-14251" );
	script_bugtraq_id( 100620 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-04 02:29:00 +0000 (Mon, 04 Dec 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "TYPO3 Unrestricted File Upload Vulnerability" );
	script_tag( name: "summary", value: "TYPO3 is prone to an unrestricted file upload vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability occurs in the fileDenyPattern in sysext/core/Classes/Core/SystemEnvironmentBuilder.php." );
	script_tag( name: "impact", value: "Remotely authenticated users may upload files with a .pht extension and may consequently execute arbitrary PHP code." );
	script_tag( name: "affected", value: "TYPO3 versions 7.6.0 to 7.6.21 and 8.0.0 to 8.7.4 are vulnerable." );
	script_tag( name: "solution", value: "Update to TYPO3 versions 7.6.22 or 8.7.5 that fix the problem described, make sure overridden settings for TYPO3_CONF_VARS/BE/fileDenyPattern are adjusted." );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1039295" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/100620" );
	script_xref( name: "URL", value: "https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2017-007/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!Port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!Ver = get_app_version( cpe: CPE, port: Port, version_regex: "[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
if(IsMatchRegexp( Ver, "^7" )){
	if(version_in_range( version: Ver, test_version: "7.6.0", test_version2: "7.6.21" )){
		fix = "7.6.22";
		VULN = TRUE;
	}
}
if(IsMatchRegexp( Ver, "^8" )){
	if(version_in_range( version: Ver, test_version: "8.0.0", test_version2: "8.7.4" )){
		fix = "8.7.5";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: Ver, fixed_version: fix );
	security_message( port: Port, data: report );
	exit( 0 );
}
exit( 99 );

