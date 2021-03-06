if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803301" );
	script_version( "2019-12-18T15:04:04+0000" );
	script_cve_id( "CVE-2013-0420" );
	script_bugtraq_id( 57383 );
	script_tag( name: "cvss_base", value: "2.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-12-18 15:04:04 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2013-02-01 12:01:15 +0530 (Fri, 01 Feb 2013)" );
	script_name( "Oracle VM VirtualBox Unspecified Vulnerability - Feb13 (Mac OS X)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_oracle_virtualbox_detect_macosx.sc" );
	script_mandatory_keys( "Oracle/VirtualBox/MacOSX/Version" );
	script_xref( name: "URL", value: "http://www.scip.ch/en/?vuldb.7413" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpujan2013-1515902.html" );
	script_tag( name: "impact", value: "Successful exploitation allows malicious local users to perform certain
  actions with escalated privileges." );
	script_tag( name: "affected", value: "Oracle VM VirtualBox versions 4.0, 4.1 and 4.2 on Mac OS X" );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error within the core component and can be
  exploited to cause a hang and manipulate certain VirtualBox accessible data." );
	script_tag( name: "summary", value: "This host is installed with Oracle VM VirtualBox and is prone to
  unspecified vulnerability." );
	script_tag( name: "solution", value: "Apply the patch listed in the referenced advisory." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:oracle:vm_virtualbox";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "4.0", test_version2: "4.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Apply the patch", install_path: location );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

