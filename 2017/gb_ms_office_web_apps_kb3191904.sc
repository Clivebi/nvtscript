CPE = "cpe:/a:microsoft:office_web_apps";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811025" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_cve_id( "CVE-2017-0254", "CVE-2017-0281" );
	script_bugtraq_id( 98101, 98297 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-08 01:29:00 +0000 (Sat, 08 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-05-10 09:00:39 +0530 (Wed, 10 May 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Office Web Apps Multiple Remote Code Execution Vulnerabilities (KB3191904)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update for Microsoft Office Web Apps according to Microsoft KB3191904" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as the software fails to
  properly handle objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to run arbitrary code in the context of the current user. If the
  current user is logged on with administrative user rights, an attacker could
  take control of the affected system. An attacker could then install programs /
  view, change, or delete data / or create new accounts with full user rights." );
	script_tag( name: "affected", value: "Microsoft Office Web Apps Server 2010 Service Pack 2 and prior." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3191904" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0254" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0281" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_office_web_apps_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/Office/Web/Apps/Ver" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
webappVer = infos["version"];
path = infos["location"];
if(!path || ContainsString( path, "Could not find the install location" )){
	exit( 0 );
}
if(IsMatchRegexp( webappVer, "^14\\..*" )){
	dllVer = fetch_file_version( sysPath: path, file_name: "\\14.0\\WebServices\\WordServer\\Core\\sword.dll" );
	if(dllVer){
		if(version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.7181.4999" )){
			report = "File checked:     " + path + "\\14.0\\WebServices\\WordServer\\Core\\sword.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "14.0 - 14.0.7181.4999" + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

