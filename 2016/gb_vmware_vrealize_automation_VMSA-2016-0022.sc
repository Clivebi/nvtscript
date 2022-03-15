CPE = "cpe:/a:vmware:vrealize_automation";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140079" );
	script_cve_id( "CVE-2016-7458", "CVE-2016-7459", "CVE-2016-7460" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_version( "2019-07-24T08:39:52+0000" );
	script_name( "VMSA-2016-0022: VMware vRealize Automation XML External Entity (XXE) Vulnerability" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0022.html" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to 6.2.5" );
	script_tag( name: "summary", value: "vRealize Automation contain an XML External Entity (XXE) vulnerability in the Single Sign-On functionality" );
	script_tag( name: "insight", value: "A specially crafted XML request issued to the server may lead to a Denial of Service or to unintended information disclosure." );
	script_tag( name: "affected", value: "vRealize Automation 6.x" );
	script_tag( name: "last_modification", value: "2019-07-24 08:39:52 +0000 (Wed, 24 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-11-23 10:12:04 +0100 (Wed, 23 Nov 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_family( "VMware Local Security Checks" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_vrealize_automation_web_detect.sc" );
	script_mandatory_keys( "vmware/vrealize/automation/version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^6\\." )){
	if(version_is_less( version: version, test_version: "6.2.5" )){
		fix = "6.2.5";
	}
	if(IsMatchRegexp( version, "^6\\.2\\.5" )){
		if(build = get_kb_item( "vmware/vrealize/automation/build" )){
			if(build && int( build ) < 4619074){
				fix = "6.2.5 Build 4619074";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

