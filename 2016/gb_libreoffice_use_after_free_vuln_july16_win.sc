CPE = "cpe:/a:libreoffice:libreoffice";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808574" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2016-4324" );
	script_bugtraq_id( 91499 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-07-12 11:01:16 +0530 (Tue, 12 Jul 2016)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "LibreOffice Use-after-free Vulnerability July16 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with LibreOffice
  and is prone to use-after-free vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to insufficient validation
  of RTF parser validity." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "LibreOffice version before 5.1.4 on Windows." );
	script_tag( name: "solution", value: "Upgrade to LibreOffice version
  5.1.4 or 5.2.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.libreoffice.org/about-us/security/advisories/cve-2016-4324" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(version_is_less( version: libreVer, test_version: "5.1.4" )){
	report = report_fixed_ver( installed_version: libreVer, fixed_version: "5.1.4 or 5.2.0" );
	security_message( data: report );
	exit( 0 );
}

