CPE = "cpe:/a:typo3:typo3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804212" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_bugtraq_id( 49072 );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-01-07 16:28:55 +0530 (Tue, 07 Jan 2014)" );
	script_name( "TYPO3 ExtDirect Missing Access Control Vulnerability" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to consume any available
ExtDirect endpoint service." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An error exists in ExtDirect, where an ExtDirect endpoints are not associated
with TYPO3 backend modules." );
	script_tag( name: "solution", value: "Upgrade to TYPO3 version 4.4.9, 4.5.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with TYPO3 and is prone missing access control
vulnerability." );
	script_tag( name: "affected", value: "TYPO3 version before 4.4.9 and 4.5.0 to 4.5.3" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45557/" );
	script_xref( name: "URL", value: "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-CORE-sa-2011-001" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "4.4.9" ) || version_in_range( version: vers, test_version: "4.5.0", test_version2: "4.5.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.4.9 / 4.5.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

