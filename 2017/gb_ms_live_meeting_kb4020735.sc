CPE = "cpe:/a:microsoft:office_live_meeting";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810946" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_cve_id( "CVE-2017-0283" );
	script_bugtraq_id( 98920 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-15 17:04:17 +0530 (Thu, 15 Jun 2017)" );
	script_name( "Microsoft Live Meeting Console Remote Code Execution Vulnerability (KB4020735)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4020735." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due the way Windows
  Uniscribe handles objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  remote attacker to execute arbitrary code on the affected system and
  take control of the affected system." );
	script_tag( name: "affected", value: "Microsoft Live Meeting 2007 Console." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/4020735" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_live_meeting_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/OfficeLiveMeeting/Ver" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4020735" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
appPath = get_app_location( cpe: CPE, skip_port: TRUE );
if(!appPath || ContainsString( appPath, "Couldn find the install location" )){
	exit( 0 );
}
dllVer = fetch_file_version( sysPath: appPath, file_name: "Ogl.dll" );
if(!dllVer){
	exit( 0 );
}
if(version_is_less( version: dllVer, test_version: "12.0.6769.5000" )){
	report = "File checked:     " + appPath + "\\Ogl.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: Less than 12.0.6769.5000\n";
	security_message( data: report );
	exit( 0 );
}

