CPE = "cpe:/a:symantec:endpoint_protection";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807056" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-03-01 14:45:27 +0530 (Tue, 01 Mar 2016)" );
	script_name( "Symantec Endpoint Protection 'ccSvcHst.exe' File Denial of Service Vulnerability Feb15" );
	script_tag( name: "summary", value: "This host is installed with Symantec
  Endpoint Protection Manager and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to insufficient
  validation of input in an unknown function of the file
  'Smc.exe/SmcGui.exe/ccSvcHst.exe'." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to cause denial of service conditions." );
	script_tag( name: "affected", value: "Symantec Endpoint Protection version
  12.1.4013." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/135185" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/535958" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_symantec_prdts_detect.sc" );
	script_mandatory_keys( "Symantec/Endpoint/Protection" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!sepVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
sepType = get_kb_item( "Symantec/SEP/SmallBusiness" );
if(isnull( sepType ) && IsMatchRegexp( sepVer, "^(12\\.1)" )){
	if(version_is_equal( version: sepVer, test_version: "12.1.4013.4013" )){
		report = report_fixed_ver( installed_version: sepVer, fixed_version: "WillNotFix" );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

