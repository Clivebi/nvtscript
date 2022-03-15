CPE = "cpe:/a:adobe:animate";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815843" );
	script_version( "2021-08-30T14:01:20+0000" );
	script_cve_id( "CVE-2019-7960" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-30 14:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-22 01:11:00 +0000 (Fri, 22 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-11-14 12:20:15 +0530 (Thu, 14 Nov 2019)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe Animate Privilege Escalation Vulnerability-Windows (apsb19-34)" );
	script_tag( name: "summary", value: "The host is installed with Adobe Illustrator
  and is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insecure library loading error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to escalate privileges on the affected system." );
	script_tag( name: "affected", value: "Adobe Animate CC 2019 19.2.1 and earlier versions on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Animate CC 2019 version
  20.0 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/animate/apsb19-34.html" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_adobe_animate_detect_win.sc" );
	script_mandatory_keys( "Adobe/Animate/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
adobeVer = infos["version"];
adobePath = infos["location"];
if(version_in_range( version: adobeVer, test_version: "19.0", test_version2: "19.2.1" )){
	report = report_fixed_ver( installed_version: adobeVer, fixed_version: "20.0", install_path: adobePath );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

