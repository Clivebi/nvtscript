CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803995" );
	script_version( "2020-10-30T06:49:18+0000" );
	script_cve_id( "CVE-2011-3584" );
	script_bugtraq_id( 49622 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2020-10-30 06:49:18 +0000 (Fri, 30 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-12-31 16:24:40 +0530 (Tue, 31 Dec 2013)" );
	script_name( "TYPO3 cHash Parsing Denial of Service Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to cause a denial of service
  condition." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error exists in TYPO3 because it fails to disable caching when
  an invalid cache hash URL parameter (cHash) is provided." );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.3.14 or 4.4.11 or 4.5.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone to denial of service
  vulnerability." );
	script_tag( name: "affected", value: "TYPO3 versions 4.2.0 to 4.2.17, 4.3.0 to 4.3.13, 4.4.0 to 4.4.10 and 4.5.0 to
  4.5.5." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45940/" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2011-003/" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_typo3_detect.sc" );
	script_mandatory_keys( "TYPO3/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(!IsMatchRegexp( vers, "[0-9]+\\.[0-9]+\\.[0-9]+" )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "4.2.0", test_version2: "4.2.17" ) || version_in_range( version: vers, test_version: "4.3.0", test_version2: "4.3.13" ) || version_in_range( version: vers, test_version: "4.4.0", test_version2: "4.4.10" ) || version_in_range( version: vers, test_version: "4.5.0", test_version2: "4.5.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.3.14 / 4.4.11 / 4.5.6" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

