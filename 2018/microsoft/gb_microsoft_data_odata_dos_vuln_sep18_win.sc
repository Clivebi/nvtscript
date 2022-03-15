if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814211" );
	script_version( "2021-06-24T11:00:30+0000" );
	script_cve_id( "CVE-2018-8269" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-09-17 14:45:59 +0530 (Mon, 17 Sep 2018)" );
	script_name( "'Microsoft.Data.OData' Denial of Service Vulnerability Sep18 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with 'OData Library'
  and is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on
  the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in how the OData
  web application handles web requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to cause a denial of service against an OData web application." );
	script_tag( name: "affected", value: "Microsoft.Data.OData library" );
	script_tag( name: "solution", value: "Upgrade to Microsoft.Data.OData library to
  version 5.8.4 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod", value: "75" );
	script_xref( name: "URL", value: "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8269" );
	script_xref( name: "URL", value: "https://www.nuget.org/packages/Microsoft.Data.OData/5.8.4" );
	script_xref( name: "URL", value: "https://odata.github.io/odata.net/v6/#ODL-5.8.4" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_wmi_access.sc", "lsc_options.sc" );
	script_mandatory_keys( "WMI/access_successful", "SMB/WindowsVersion" );
	script_exclude_keys( "win/lsc/disable_wmi_search" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("misc_func.inc.sc");
require("wmi_file.inc.sc");
require("list_array_func.inc.sc");
infos = kb_smb_wmi_connectinfo();
if(!infos){
	exit( 0 );
}
handle = wmi_connect( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"] );
if(!handle){
	exit( 0 );
}
fileList = wmi_file_fileversion( handle: handle, fileName: "Microsoft.Data.OData", includeHeader: FALSE );
wmi_close( wmi_handle: handle );
if(!fileList || !is_array( fileList )){
	exit( 0 );
}
report = "";
for filePath in keys( fileList ) {
	vers = fileList[filePath];
	if(vers && version = eregmatch( string: vers, pattern: "^([0-9.]+)" )){
		if(version_is_less( version: version[1], test_version: "5.8.4" )){
			VULN = TRUE;
			report += report_fixed_ver( file_version: version[1], file_checked: filePath, fixed_version: "5.8.4" ) + "\n";
		}
	}
}
if(VULN){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

