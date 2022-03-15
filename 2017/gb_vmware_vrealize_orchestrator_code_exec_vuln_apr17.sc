CPE = "cpe:/a:vmware:vrealize_orchestrator";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811005" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_cve_id( "CVE-2015-6934" );
	script_bugtraq_id( 79648 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-11-28 19:40:00 +0000 (Mon, 28 Nov 2016)" );
	script_tag( name: "creation_date", value: "2017-04-20 18:03:53 +0530 (Thu, 20 Apr 2017)" );
	script_name( "VMware vRealize Orchestrator Remote Code Execution Vulnerability - Apr17" );
	script_tag( name: "summary", value: "This host is running VMware vRealize
  Orchestrator and is prone to code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a deserialization error
  involving Apache Commons-collections and a specially constructed chain of
  classes exists." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of current user." );
	script_tag( name: "affected", value: "VMware vRealize Orchestrator 6.x before
  6.0.5, 4.2.x and 5.x" );
	script_tag( name: "solution", value: "Upgrade VMware vRealize Orchestrator to
  version 6.0.5 or apply patch available from vendor." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2015-0009.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_vmware_vrealize_orchestrator_web_detect.sc" );
	script_mandatory_keys( "vmware/vrealize/orchestrator/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vmPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vmVer = get_app_version( cpe: CPE, port: vmPort )){
	exit( 0 );
}
if(IsMatchRegexp( vmVer, "^(4\\.2\\.)" ) || IsMatchRegexp( vmVer, "^(5\\.)" )){
	VULN = TRUE;
	fix = "Apply Patch from Vendor";
}
if(IsMatchRegexp( vmVer, "^(6\\.)" )){
	if(version_in_range( version: vmVer, test_version: "6.0", test_version2: "6.0.4" )){
		VULN = TRUE;
		fix = "6.0.5 or Apply Patch from Vendor";
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vmVer, fixed_version: "6.0.5" );
	security_message( data: report, port: vmPort );
	exit( 0 );
}

