CPE = "cpe:/a:ibm:tivoli_storage_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811221" );
	script_version( "2021-09-09T12:15:00+0000" );
	script_cve_id( "CVE-2016-8939" );
	script_bugtraq_id( 98783 );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-09 12:15:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-16 02:29:00 +0000 (Tue, 16 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-06-23 11:09:21 +0530 (Fri, 23 Jun 2017)" );
	script_name( "IBM TSM Client 'password' Information Disclosure Vulnerability - Windows" );
	script_tag( name: "summary", value: "This host is installed with IBM Tivoli Storage
  Manager Client and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to error in the IBM Tivoli
  Storage Manager (IBM Spectrum Protect) clients/agents which store password
  information in the Windows Registry in a manner which can be compromised." );
	script_tag( name: "impact", value: "Successful exploitation will allow a local
  attacker to gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "Tivoli Storage Manager Client versions
  7.1 all levels, 8.1 all levels, 6.4 all levels and 6.3 and below on Windows.

  - ---
  NOTE: 6.3 and below which are all EOS.

  - ---" );
	script_tag( name: "solution", value: "Workarounds and Mitigations are available." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_xref( name: "URL", value: "http://www.ibm.com/support/docview.wss?uid=swg22003738" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_ibm_tsm_client_detect.sc" );
	script_mandatory_keys( "IBM/Tivoli/Storage/Manager/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!tivVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( tivVer, "^((7\\.1)|(8\\.1)|(6\\.(3|4)))" )){
	report = report_fixed_ver( installed_version: tivVer, fixed_version: "Apply Mitigation" );
	security_message( data: report );
	exit( 0 );
}

