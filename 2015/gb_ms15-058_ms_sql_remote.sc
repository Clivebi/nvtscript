if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805815" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-1761", "CVE-2015-1762", "CVE-2015-1763" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-07-15 12:57:38 +0530 (Wed, 15 Jul 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Microsoft SQL Server Multiple Vulnerabilities (3065718) - Remote" );
	script_tag( name: "summary", value: "This host is missing an important
  security update according to Microsoft Bulletin MS15-058." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws exist due to:

  - An improperly casts pointers to an incorrect class.

  - An incorrectly handling internal function calls to uninitialized memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to elevate the privileges or execute arbitrary code remotely." );
	script_tag( name: "affected", value: "- Microsoft SQL Server 2008 for x86/x64 Service Pack 3

  - Microsoft SQL Server 2008 for x86/x64 Service Pack 4

  - Microsoft SQL Server 2008 R2 for x86/x64 Service Pack 2

  - Microsoft SQL Server 2008 R2 for x86/x64 Service Pack 3

  - Microsoft SQL Server 2012 for x86/x64 Service Pack 1

  - Microsoft SQL Server 2012 for x86/x64 Service Pack 2

  - Microsoft SQL Server 2014 for x86/x64" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3065718" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-058" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "mssqlserver_detect.sc" );
	script_mandatory_keys( "MS/SQLSERVER/Running" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
cpe_list = make_list( "cpe:/a:microsoft:sql_server_2014",
	 "cpe:/a:microsoft:sql_server_2012:sp1",
	 "cpe:/a:microsoft:sql_server_2012:sp2",
	 "cpe:/a:microsoft:sql_server_2008:r2:sp2",
	 "cpe:/a:microsoft:sql_server_2008:r2:sp3",
	 "cpe:/a:microsoft:sql_server_2008:sp3",
	 "cpe:/a:microsoft:sql_server_2008:sp4" );
if(!infos = get_app_port_from_list( cpe_list: cpe_list )){
	exit( 0 );
}
port = infos["port"];
cpe = infos["cpe"];
if(!vers = get_app_version( cpe: cpe, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^12\\.0" )){
	if(version_in_range( version: vers, test_version: "12.0.2000.80", test_version2: "12.0.2268.0" ) || version_in_range( version: vers, test_version: "12.0.2300", test_version2: "12.0.2547" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "12.0.2000.80 - 12.0.2268.0 / 12.0.2300 - 12.0.2547" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( vers, "^11\\.0" )){
	if(version_in_range( version: vers, test_version: "11.00.3000.00", test_version2: "11.0.3155" ) || version_in_range( version: vers, test_version: "11.0.3300", test_version2: "11.0.3512" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "11.00.3000.00 - 11.0.3155 / 11.0.3300 - 11.0.3512" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( vers, "^11\\.0" )){
	if(version_in_range( version: vers, test_version: "11.0.5058.0", test_version2: "11.0.5342" ) || version_in_range( version: vers, test_version: "11.0.5600", test_version2: "11.0.5612" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "11.0.5058.0 - 11.0.5342 / 11.0.5600 - 11.0.5612" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( vers, "^10\\.50" )){
	if(version_in_range( version: vers, test_version: "10.50.4000.0", test_version2: "10.50.4041" ) || version_in_range( version: vers, test_version: "10.50.4300", test_version2: "10.50.4338" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "10.50.4000.0 - 10.50.4041 / 10.50.4300 - 10.50.4338" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( vers, "^10\\.50" )){
	if(version_in_range( version: vers, test_version: "10.50.6000.34", test_version2: "10.50.6219" ) || version_in_range( version: vers, test_version: "10.50.6500", test_version2: "10.50.6528" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "10.50.6000.34 - 10.50.6219 / 10.50.6500 - 10.50.6528" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( vers, "^10\\.0" )){
	if(version_in_range( version: vers, test_version: "10.00.5500.00", test_version2: "10.0.5537" ) || version_in_range( version: vers, test_version: "10.0.5750", test_version2: "10.0.5889" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "10.00.5500.00 - 10.0.5537 / 10.0.5750 - 10.0.5889" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( vers, "^10\\.0" )){
	if(version_in_range( version: vers, test_version: "10.00.6000.29", test_version2: "10.0.6240" ) || version_in_range( version: vers, test_version: "10.0.6500", test_version2: "10.0.6534" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "10.00.6000.29 - 10.0.6240 / 10.0.6500 - 10.0.6534" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

