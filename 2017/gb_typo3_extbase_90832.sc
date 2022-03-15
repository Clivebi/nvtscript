CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108058" );
	script_version( "2021-09-15T11:15:39+0000" );
	script_cve_id( "CVE-2016-5091" );
	script_bugtraq_id( 90832 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-15 11:15:39 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-26 16:39:00 +0000 (Thu, 26 Jan 2017)" );
	script_tag( name: "creation_date", value: "2017-01-25 13:00:00 +0100 (Wed, 25 Jan 2017)" );
	script_name( "TYPO3 Extbase Remote Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/90832" );
	script_xref( name: "URL", value: "https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2016-013/" );
	script_tag( name: "impact", value: "A remote attacker can leverage this issue to execute arbitrary code within the context
  of the application. Successful exploits will compromise the application and possibly the underlying system." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Extbase request handling fails to implement a proper access check for requested
  controller/ action combinations, which makes it possible for an attacker to execute arbitrary Extbase actions by
  crafting a special request. To successfully exploit this vulnerability, an attacker must have access to at least
  one Extbase plugin or module action in a TYPO3 installation." );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 6.2.24, 7.6.8 or 8.1.1 or later." );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to a remote code-execution vulnerability." );
	script_tag( name: "affected", value: "TYPO3 versions from 4.3.0 to 6.2.23, 7.x before 7.6.8, and 8.1.0" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://typo3.org/" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port, version_regex: "[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "4.3.0", test_version2: "6.2.23" )){
	vuln = TRUE;
	fix = "6.2.24";
}
if(IsMatchRegexp( vers, "^7" )){
	if(version_is_less( version: vers, test_version: "7.6.8" )){
		vuln = TRUE;
		fix = "7.6.8";
	}
}
if(version_is_equal( version: vers, test_version: "8.1.0" )){
	vuln = TRUE;
	fix = "8.1.1";
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

