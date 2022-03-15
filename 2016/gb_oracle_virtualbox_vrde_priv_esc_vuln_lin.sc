CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809079" );
	script_version( "2019-07-05T09:12:25+0000" );
	script_cve_id( "CVE-2016-5605" );
	script_bugtraq_id( 93685 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-07-05 09:12:25 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-10-21 14:40:28 +0530 (Fri, 21 Oct 2016)" );
	script_name( "Oracle Virtualbox VRDE Privilege Escalation Vulnerability (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Oracle VM
  VirtualBox and is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error in
  VirtualBox Remote Desktop Extension (VRDE) sub component." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to access and modify data." );
	script_tag( name: "affected", value: "VirtualBox versions prior to 5.1.4 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Oracle VirtualBox version
  5.1.4 or later on Linux." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "secpod_sun_virtualbox_detect_lin.sc" );
	script_mandatory_keys( "Sun/VirtualBox/Lin/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!virtualVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( virtualVer, "^5\\.1\\." )){
	if(version_is_less( version: virtualVer, test_version: "5.1.4" )){
		report = report_fixed_ver( installed_version: virtualVer, fixed_version: "5.1.4" );
		security_message( data: report );
		exit( 0 );
	}
}

