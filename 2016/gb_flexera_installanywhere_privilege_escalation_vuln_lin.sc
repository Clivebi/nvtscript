CPE = "cpe:/a:flexerasoftware:installanywhere";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809018" );
	script_version( "$Revision: 12313 $" );
	script_cve_id( "CVE-2016-4560" );
	script_bugtraq_id( 90979 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-08-29 13:05:30 +0530 (Mon, 29 Aug 2016)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_name( "Flexera InstallAnywhere Privilege Escalation Vulnerability (Linux)" );
	script_tag( name: "summary", value: "The host is installed with Flexera
  InstallAnywhere and is prone to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an untrusted search path
  vulnerability in Flexera InstallAnywhere." );
	script_tag( name: "impact", value: "Successful exploitation will allow a local
  attacker to gain privileges via a Trojan horse DLL in the current working
  directory of a setup-launcher executable file." );
	script_tag( name: "affected", value: "Flexera InstallAnywhere all versions on Linux." );
	script_tag( name: "solution", value: "Apply the hotfix from the link mentioned in
  reference." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://flexeracommunity.force.com/customer/articles/INFO/Best-Practices-to-Avoid-Windows-Setup-Launcher-Executable-Issues" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_flexera_installanywhere_detect_lin.sc" );
	script_mandatory_keys( "InstallAnywhere/Linux/Ver" );
	script_xref( name: "URL", value: "http://www.flexerasoftware.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!installVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: installVer, test_version: "17.0" )){
	report = report_fixed_ver( installed_version: installVer, fixed_version: "Apply the hotfix" );
	security_message( data: report );
	exit( 0 );
}

