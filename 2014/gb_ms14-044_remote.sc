if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805110" );
	script_version( "2021-04-08T12:57:28+0000" );
	script_cve_id( "CVE-2014-1820", "CVE-2014-4061" );
	script_bugtraq_id( 69071, 69088 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-04-08 12:57:28 +0000 (Thu, 08 Apr 2021)" );
	script_tag( name: "creation_date", value: "2014-12-01 16:03:48 +0530 (Mon, 01 Dec 2014)" );
	script_name( "Microsoft SQL Server Elevation of Privilege Vulnerability (2984340) - Remote" );
	script_tag( name: "summary", value: "This host is missing an important
  security update according to Microsoft Bulletin MS14-044." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws are due to when,

  - SQL Master Data Services (MDS) does not properly encode output.

  - SQL Server processes an incorrectly formatted T-SQL query." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a Denial of Service or elevation of privilege." );
	script_tag( name: "affected", value: "- Microsoft SQL Server 2014 x64

  - Microsoft SQL Server 2012 x86/x64 Service Pack 1 and prior

  - Microsoft SQL Server 2008 R2 x86/x64 Service Pack 2 and prior

  - Microsoft SQL Server 2008 x86/x64 Service Pack 3 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS14-044" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "mssqlserver_detect.sc" );
	script_mandatory_keys( "MS/SQLSERVER/Running" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
cpe_list = make_list( "cpe:/a:microsoft:sql_server_2014",
	 "cpe:/a:microsoft:sql_server_2012:sp1",
	 "cpe:/a:microsoft:sql_server_2008:r2:sp2" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
port = infos["port"];
cpe = infos["cpe"];
if(!vers = get_app_version( cpe: cpe, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^12\\.0" )){
	if(version_in_range( version: vers, test_version: "12.0.2000", test_version2: "12.0.2253" ) || version_in_range( version: vers, test_version: "12.0.2300", test_version2: "12.0.2380" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "12.0.2000 - 12.0.2253 / 12.0.2300 - 12.0.2380" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( vers, "^11\\.0" )){
	if(version_in_range( version: vers, test_version: "11.0.3000", test_version2: "11.0.3152" ) || version_in_range( version: vers, test_version: "11.0.3300", test_version2: "11.0.3459" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "11.0.3000 - 11.0.3152 / 11.0.3300 - 11.0.3459" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( vers, "^10\\.50" )){
	if(version_in_range( version: vers, test_version: "10.50.4000", test_version2: "10.50.4032" ) || version_in_range( version: vers, test_version: "10.50.4251", test_version2: "10.50.4320" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "10.50.4000 - 10.50.4032 / 10.50.4251 - 10.50.4320" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( vers, "^10\\.0" )){
	if(version_in_range( version: vers, test_version: "10.0.5500", test_version2: "10.0.5519" ) || version_in_range( version: vers, test_version: "10.0.5750", test_version2: "10.0.5868" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "10.0.5500 - 10.0.5519 / 10.0.5750 - 10.0.5868" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

