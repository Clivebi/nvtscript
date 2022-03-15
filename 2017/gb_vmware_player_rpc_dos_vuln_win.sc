CPE = "cpe:/a:vmware:player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810679" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_cve_id( "CVE-2015-2341" );
	script_bugtraq_id( 75094 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-04-07 17:39:57 +0530 (Fri, 07 Apr 2017)" );
	script_name( "VMware Player 'RPC Command' Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with VMware Player
  and is prone to denial-of-service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an input validation
  issue on an RPC command." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct a denial of service condition." );
	script_tag( name: "affected", value: "VMware Player 6.x before 6.0.6
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to VMware Player version
  6.0.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2015-0004.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_vmware_prdts_detect_win.sc" );
	script_mandatory_keys( "VMware/Player/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vmwareVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( vmwareVer, "^6\\." )){
	if(version_is_less( version: vmwareVer, test_version: "6.0.6" )){
		report = report_fixed_ver( installed_version: vmwareVer, fixed_version: "6.0.6" );
		security_message( data: report );
		exit( 0 );
	}
}

