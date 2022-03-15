CPE = "cpe:/a:microsoft:sql_server_2014:sp2";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811290" );
	script_version( "2021-09-08T14:01:33+0000" );
	script_cve_id( "CVE-2017-8516" );
	script_bugtraq_id( 100041 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-08 14:01:33 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-14 18:02:00 +0000 (Mon, 14 Aug 2017)" );
	script_tag( name: "creation_date", value: "2017-08-09 15:20:35 +0530 (Wed, 09 Aug 2017)" );
	script_name( "Microsoft SQL Server Information Disclosure Vulnerability-KB4036996 (Remote)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4036996" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in Microsoft
  SQL Server Analysis Services when it improperly enforces permissions." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain access to sensitive information and access to an affected SQL server
  database." );
	script_tag( name: "affected", value: "Microsoft SQL Server 2014 Service Pack 2 for x86/x64-based Systems (CU)." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4036996" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "mssqlserver_detect.sc" );
	script_mandatory_keys( "MS/SQLSERVER/Running" );
	script_require_ports( 1433 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "12.0.5400.0", test_version2: "12.0.5552.0" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "12.0.5400.0 - 12.0.5552.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

