CPE = "cpe:/a:microsoft:onedrive";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817379" );
	script_version( "2021-08-12T06:00:50+0000" );
	script_cve_id( "CVE-2020-16852", "CVE-2020-16853", "CVE-2020-16851" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 06:00:50 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-14 14:04:00 +0000 (Mon, 14 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-09 09:00:21 +0530 (Wed, 09 Sep 2020)" );
	script_name( "Microsoft OneDrive Multiple Vulnerabilities - Sep 2020" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Security Updates for month of September" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to errors when the OneDrive for Windows
  Desktop application improperly handles symbolic links." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain elevated privileges and overwrite a targeted file with an elevated status." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see
  the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-16852" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-16851" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-16853" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/office/onedrive-release-notes-845dcf18-f921-435e-bf28-4e24b95e5fc0" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_microsoft_onedrive_detect_win.sc" );
	script_mandatory_keys( "microsoft/onedrive/win/detected" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(!version || IsMatchRegexp( version, "Unknown" )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "20.170.0824.0001" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "20.170.0824.0001", install_path: path );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

