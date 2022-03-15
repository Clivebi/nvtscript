if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107360" );
	script_version( "2021-05-27T09:28:58+0000" );
	script_cve_id( "CVE-2018-3970", "CVE-2018-3971" );
	script_tag( name: "last_modification", value: "2021-05-27 09:28:58 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-11-01 14:04:55 +0100 (Thu, 01 Nov 2018)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-25 19:59:00 +0000 (Fri, 25 Jan 2019)" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Sophos HitmanPro.Alert Multiple Vulnerabilities (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_sophos_hitmanproalertx86_detect_win.sc" );
	script_mandatory_keys( "Sophos/HitmanPro.Alert/Win/detected" );
	script_tag( name: "summary", value: "Sophos HitmanPro.Alert version 3.7.6.744 is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "- An exploitable arbitrary write vulnerability exists in the 0x2222CC IOCTL handler functionality of Sophos HitmanPro.Alert 3.7.6.744.

  - A specially crafted IRP request can cause the driver to write data under controlled by an attacker address, resulting in memory corruption.

  - Additionally an exploitable memory disclosure vulnerability exists in the 0x222000 IOCTL handler functionality.

  - A specially crafted IRP request can cause the driver to return uninitialized memory, resulting in kernel memory disclosure. An attacker can send an IRP request to trigger these vulnerabilities." );
	script_tag( name: "affected", value: "Sophos HitmanPro.Alert version 3.7.6.744." );
	script_tag( name: "solution", value: "Upgrade to Sophos HitmanPro.Alert 3.7.9 or later." );
	script_xref( name: "URL", value: "https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0635" );
	script_xref( name: "URL", value: "https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0636" );
	script_xref( name: "URL", value: "https://www.hitmanpro.com/en-us/downloads.aspx" );
	exit( 0 );
}
CPE = "cpe:/a:sophos:hitmanpro.alert";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "3.0", test_version2: "3.7.6.744" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.7.9.759", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

