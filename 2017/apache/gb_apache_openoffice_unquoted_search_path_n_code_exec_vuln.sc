CPE = "cpe:/a:openoffice:openoffice.org";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812223" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_cve_id( "CVE-2016-6803", "CVE-2016-6804" );
	script_bugtraq_id( 94418, 93774 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-29 17:15:00 +0000 (Wed, 29 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-11-22 15:10:57 +0530 (Wed, 22 Nov 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Apache OpenOffice 'Unquoted Search Path' And Remote Code Execution Vulnerabilities" );
	script_tag( name: "summary", value: "The host is installed with Apache
  OpenOffice and is prone to an unquoted windows search path and remote code
  execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Apache OpenOffice installer for Windows contained a defective operation that
    could trigger execution of unwanted software installed by a Trojan Horse
    application.

  - A defective operation in Apache OpenOffice installer." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  remote attacker to trigger execution of unwanted software installed by
  a Trojan Horse application and allows execution of arbitrary code with
  elevated privileges." );
	script_tag( name: "affected", value: "Apache OpenOffice before 4.1.3 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Apache OpenOffice 4.1.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.securitytracker.com/id/1037015" );
	script_xref( name: "URL", value: "https://www.openoffice.org/security/cves/CVE-2016-6803.html" );
	script_xref( name: "URL", value: "https://www.openoffice.org/security/cves/CVE-2016-6804.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_openoffice_detect_win.sc" );
	script_mandatory_keys( "OpenOffice/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
openoffcVer = infos["version"];
openoffcpath = infos["location"];
if(version_is_less( version: openoffcVer, test_version: "4.13.9783" )){
	report = report_fixed_ver( installed_version: openoffcVer, fixed_version: "4.1.3", install_path: openoffcpath );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

