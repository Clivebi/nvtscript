CPE = "cpe:/a:avast:antivirus";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808058" );
	script_version( "2021-03-30T06:46:39+0000" );
	script_cve_id( "CVE-2015-8620" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-03-30 06:46:39 +0000 (Tue, 30 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-06-03 18:38:44 +0530 (Fri, 03 Jun 2016)" );
	script_name( "Avast Free Antivirus Heap-Based Buffer Overflow Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Avast Free
  Antivirus and is prone to heap-based buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in avast virtualization
  driver (aswSnx.sys) that handles 'Sandbox' and 'DeepScreen' functionality
  improperly." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to elevate privileges from any account type and execute code as SYSTEM." );
	script_tag( name: "affected", value: "Avast Free Antivirus version before
  11.1.2253." );
	script_tag( name: "solution", value: "Upgrade to Avast Free Antivirus version
  11.1.2253 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2016/Feb/94" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_avast_av_detect_win.sc" );
	script_mandatory_keys( "avast/antivirus_free/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "11.1.2253" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.1.2253", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

