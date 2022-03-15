CPE = "cpe:/a:libreoffice:libreoffice";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810578" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_cve_id( "CVE-2017-3157" );
	script_bugtraq_id( 96402 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-08 18:51:00 +0000 (Wed, 08 May 2019)" );
	script_tag( name: "creation_date", value: "2017-03-07 12:02:02 +0530 (Tue, 07 Mar 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "LibreOffice Calc And Writer File Disclosure Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with LibreOffice
  and is prone to arbitrary file disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as embedded Objects in
  writer and calc can contain previews of their content. A document can be
  crafted which contains an embedded object that is a link to an existing file
  on the targets system. On load the preview of the embedded object will be
  updated to reflect the content of the file on the target system." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  attacker to obtain sensitive information that may aid in launching further
  attacks." );
	script_tag( name: "affected", value: "LibreOffice version prior to 5.1.6, 5.2.x
  prior to 5.2.5 on Windows." );
	script_tag( name: "solution", value: "Upgrade to LibreOffice version
  5.1.6 or 5.2.5 or 5.3.0 later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1037893" );
	script_xref( name: "URL", value: "http://www.libreoffice.org/about-us/security/advisories/cve-2017-3157" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_libreoffice_detect_portable_win.sc" );
	script_mandatory_keys( "LibreOffice/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!libreVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if( version_is_less( version: libreVer, test_version: "5.1.6" ) ){
	fix = "5.1.6";
	VULN = TRUE;
}
else {
	if(version_in_range( version: libreVer, test_version: "5.2.0", test_version2: "5.2.4" )){
		fix = "5.2.5 or 5.3.0";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: libreVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

