CPE = "cpe:/a:microsoft:sql_server_2012:sp3";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811570" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_cve_id( "CVE-2017-8516" );
	script_bugtraq_id( 100041 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-14 18:02:00 +0000 (Mon, 14 Aug 2017)" );
	script_tag( name: "creation_date", value: "2017-08-09 17:30:22 +0530 (Wed, 09 Aug 2017)" );
	script_name( "Microsoft SQL Server 2012 Information Disclosure Vulnerability-KB4019092(Remote)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4019092" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the microsoft SQL
  Server Analysis Services improperly enforces permissions." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  an attacker to access affected SQL server database." );
	script_tag( name: "affected", value: "Microsoft SQL Server 2012 Service Pack 3." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4019092" );
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
if(version_in_range( version: vers, test_version: "11.0.6000.0", test_version2: "11.0.6250.0" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "11.0.6000.0 - 11.0.6250.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

