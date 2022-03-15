CPE = "cpe:/a:mcafee:virusscan_enterprise";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808083" );
	script_version( "$Revision: 11922 $" );
	script_cve_id( "CVE-2016-4534" );
	script_tag( name: "cvss_base", value: "3.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:S/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-16 12:24:25 +0200 (Tue, 16 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-06-16 16:28:59 +0530 (Thu, 16 Jun 2016)" );
	script_name( "McAfee VirusScan Enterprise Security Bypass Vulnerability- June 16" );
	script_tag( name: "summary", value: "This host is installed with McAfee VirusScan
  Enterprise and is prone to security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in antivirus engine which
  disable engine without knowing the correct management password ." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  administrators to bypass intended self-protection rules and unlock the console
  window by closing registry handles." );
	script_tag( name: "affected", value: "McAfee VirusScan Enterprise versions before
  8.8.0 Patch 6/7 Hotfix 1123565." );
	script_tag( name: "solution", value: "Upgrade to McAfee VirusScan Enterprise
  version 8.8.0 Patch 6/7 Hotfix 1123565 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://kc.mcafee.com/resources/sites/MCAFEE/content/live/PRODUCT_DOCUMENTATION/26000/PD26485/en_US/VSE_8_8_HF1123565_release_notes.pdf" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_mcafee_virusscan_enterprise_detect_win.sc" );
	script_mandatory_keys( "McAfee/VirusScan/Win/Ver" );
	script_xref( name: "URL", value: "http://www.mcafee.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!mcafVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: mcafVer, test_version: "8.8.0.1546" )){
	report = report_fixed_ver( installed_version: mcafVer, fixed_version: "8.8.0 Patch 6/7 Hotfix 1123565 (8.8.0.1546)" );
	security_message( data: report );
	exit( 0 );
}

