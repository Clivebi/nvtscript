CPE = "cpe:/a:microsoft:project_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812205" );
	script_version( "2021-09-14T12:01:45+0000" );
	script_cve_id( "CVE-2017-11876" );
	script_bugtraq_id( 101754 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-14 12:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-30 19:40:00 +0000 (Thu, 30 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-11-15 09:49:22 +0530 (Wed, 15 Nov 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Project Server 2013 Elevation of Privilege Vulnerability (KB4011257)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4011257" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to microsoft project
  server does not properly manage user sessions." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to read content, use the victim's identity to take actions on the
  web application on behalf of the victim, such as change permissions and
  delete content, and inject malicious content in the browser of the victim." );
	script_tag( name: "affected", value: "Microsoft Project Server 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4011257" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_project_server_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/ProjectServer/Server/Ver" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
psVer = get_app_version( cpe: CPE );
if(!psVer){
	exit( 0 );
}
if(IsMatchRegexp( psVer, "^15\\..*" )){
	path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
	if(path){
		path = path + "\\Microsoft Shared\\web server extensions\\15\\CONFIG\\BIN";
		dllVer = fetch_file_version( sysPath: path, file_name: "microsoft.office.project.server.pwa.applicationpages.dll" );
		if(dllVer && IsMatchRegexp( dllVer, "^15\\." )){
			if(version_is_less( version: dllVer, test_version: "15.0.4981.1000" )){
				report = report_fixed_ver( file_checked: path + "\\Microsoft.office.project.server.pwa.applicationpages.dll", file_version: dllVer, vulnerable_range: "15.0 - 15.0.4981.999" );
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

