CPE = "cpe:/a:samsung:ipolis_device_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805482" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2015-0555" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2015-03-20 15:38:22 +0530 (Fri, 20 Mar 2015)" );
	script_name( "Samsung iPOLiS Device Manager Buffer Overflow Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Samsung iPOLiS
  Device Manager and is prone to buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to Buffer overflow in
  the XnsSdkDeviceIpInstaller.ocx ActiveX control in Samsung iPOLiS Device Manager." );
	script_tag( name: "impact", value: "Successful exploitation will allow a
  context-dependent attacker to execute arbitrary code or cause a denial of service." );
	script_tag( name: "affected", value: "Samsung iPOLiS Device Manager version 1.12.2" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Feb/81" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_samsung_iPOLis_manager_detect.sc" );
	script_mandatory_keys( "Samsung/iPOLiS_Device_Manager/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!Ver = ( get_app_version( cpe: CPE ) )){
	exit( 0 );
}
if(version_is_equal( version: Ver, test_version: "1.12.2" )){
	VULN = TRUE;
	fix = "WillNotFix";
}
if(VULN){
	report = report_fixed_ver( installed_version: Ver, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

