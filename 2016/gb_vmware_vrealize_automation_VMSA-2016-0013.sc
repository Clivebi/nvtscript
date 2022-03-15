CPE = "cpe:/a:vmware:vrealize_automation";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105881" );
	script_cve_id( "CVE-2016-5335", "CVE-2016-5336" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 12051 $" );
	script_name( "VMSA-2016-0013: VMware vRealize Automation updates address multiple security issues" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0013.html" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to 7.1 or newer" );
	script_tag( name: "summary", value: "VMware vRealize Automation updates address multiple security issues" );
	script_tag( name: "insight", value: "VMware vRealize Automation contain a vulnerability that may allow for a local privilege escalation. Exploitation of this issue may lead to
an attacker with access to a low-privileged account to escalate their privileges to that of root.

vRealize Automation contains also a vulnerability that may allow for remote code execution. Exploitation of this issue may lead to an attacker gaining access to a
low-privileged account on the appliance." );
	script_tag( name: "affected", value: "vRealize Automation 7.0.x" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-08-25 12:46:41 +0200 (Thu, 25 Aug 2016)" );
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
if(IsMatchRegexp( version, "^7\\." )){
	if(version_is_less( version: version, test_version: "7.1.0" )){
		fix = "7.1.0";
	}
	if(version == "7.1.0"){
		if(version_is_less( version: version, test_version: "7.1.0.710" )){
			fix = "7.1.0.710";
		}
	}
	if(version == "7.1.0.710"){
		if(build = get_kb_item( "vmware/vrealize/automation/build" )){
			if(build && int( build ) < 4270058){
				fix = "7.1.0.710 Build 4270058";
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

