if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811189" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_cve_id( "CVE-2017-8509", "CVE-2017-8511", "CVE-2017-8512", "CVE-2017-8514" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-15 21:30:22 +0530 (Thu, 15 Jun 2017)" );
	script_name( "Microsoft SharePoint Enterprise Server 2013 Unspecified Vulnerability (KB3203387)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB3203387" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to cause some unspecified impact." );
	script_tag( name: "affected", value: "Microsoft SharePoint Enterprise Server 2013 Service Pack 1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/3203387" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_sharepoint_sever_n_foundation_detect.sc" );
	script_mandatory_keys( "MS/SharePoint/Server/Ver" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: "cpe:/a:microsoft:sharepoint_server", exit_no_version: TRUE )){
	exit( 0 );
}
shareVer = infos["version"];
if(!shareVer || !IsMatchRegexp( shareVer, "^15\\." )){
	exit( 0 );
}
path = infos["location"];
if(!path || ContainsString( path, "Could not find the install location" )){
	exit( 0 );
}
if(IsMatchRegexp( shareVer, "^15\\." )){
	path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Office15.WSS", item: "InstallLocation" );
	if(path){
		path = path + "\\15.0\\WebServices\\ConversionServices";
		dllVer = fetch_file_version( sysPath: path, file_name: "msoserver.dll" );
		if(dllVer && IsMatchRegexp( dllVer, "^15\\." )){
			if(version_is_less( version: dllVer, test_version: "15.0.4937.0999" )){
				report = "File checked:     " + path + "\\msoserver.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + "15.0 - 15.0.4937.0999" + "\n";
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

