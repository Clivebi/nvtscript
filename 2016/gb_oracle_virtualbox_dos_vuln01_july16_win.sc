CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808258" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_cve_id( "CVE-2016-3597" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-07-21 12:24:33 +0530 (Thu, 21 Jul 2016)" );
	script_name( "Oracle Virtualbox Denial of Service Vulnerability-01 July16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Oracle VM
  VirtualBox and is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified
  error in the Oracle VM VirtualBox Core component." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  attackers to have an impact on availability." );
	script_tag( name: "affected", value: "VirtualBox versions prior to 5.0.26
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox version
  5.0.26 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_sun_virtualbox_detect_win.sc" );
	script_mandatory_keys( "Oracle/VirtualBox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!virtualVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( virtualVer, "^5\\.0\\." )){
	if(version_in_range( version: virtualVer, test_version: "5.0.0", test_version2: "5.0.25" )){
		report = report_fixed_ver( installed_version: virtualVer, fixed_version: "5.0.26" );
		security_message( data: report );
		exit( 0 );
	}
}

