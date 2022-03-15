CPE = "cpe:/a:microsoft:project_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810948" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_cve_id( "CVE-2017-8551" );
	script_bugtraq_id( 98913 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-19 14:05:00 +0000 (Tue, 19 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-06-16 11:00:41 +0530 (Fri, 16 Jun 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Project Server 2013 XSS Vulnerability (KB3203399)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3203399" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when SharePoint Server does
  not properly sanitize a specially crafted web request to an affected
  SharePoint server." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker who successfully exploited the vulnerability to perform
  cross-site scripting attacks on affected systems and run script in the
  security context of the current user." );
	script_tag( name: "affected", value: "Microsoft Project Server 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3203399" );
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
			if(version_is_less( version: dllVer, test_version: "15.0.4919.1000" )){
				report = "File checked:     " + path + "\\Microsoft.office.project.server.pwa.applicationpages.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "15.0 - 15.0.4919.999" + "\n";
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}

