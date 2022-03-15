CPE = "cpe:/a:ibm:tivoli_storage_manager_fastback";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807003" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-12-17 11:46:51 +0530 (Thu, 17 Dec 2015)" );
	script_name( "IBM Tivoli Storage Manager FastBack Server Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with IBM Tivoli Storage
  Manager FastBack and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A stack buffer overflow in the _FXCLI_SetConfFileChunk function caused by the
    insecure usage of _sscanf while parsing user-controlled input.

  - A stack buffer overflow in the _FXCLI_GetConfFileChunk function caused by the
    insecure usage of _sscanf while parsing user-controlled input.

  - Some invalid pointer dereference error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to crash the server." );
	script_tag( name: "affected", value: "IBM Tivoli Storage Manager FastBack server
  version 5.5.4.2" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/38978" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/38979" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/38980" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ibm_tsm_fastback_detect.sc" );
	script_mandatory_keys( "IBM/Tivoli/Storage/Manager/FastBack/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!tivVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: tivVer, test_version: "5.5.4.2" )){
	report = "Installed version: " + tivVer + "\n" + "Fixed version:     " + "None Available" + "\n";
	security_message( data: report );
	exit( 0 );
}

