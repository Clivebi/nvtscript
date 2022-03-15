CPE = "cpe:/a:vmware:vrealize_log_insight";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105752" );
	script_cve_id( "CVE-2016-2081", "CVE-2016-2082" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_name( "VMSA-2016-0008: VMware vRealize Log Insight addresses important and moderate security issues" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0008.html" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "a. Important stored cross-site scripting issue in VMware vRealize Log Insight
VMware vRealize Log Insight contains a vulnerability that may allow for a stored cross-site scripting attack. Exploitation of this issue may lead to the hijack of an authenticated user's session.

b. Moderate cross-site request forgery issue in VMware vRealize Log Insight
VMware vRealize Log Insight contains a vulnerability that may allow for a cross-site request forgery attack. Exploitation of this issue may lead to an attacker replacing trusted content in the Log Insight UI without the user's authorization." );
	script_tag( name: "solution", value: "Apply the missing patch(es)." );
	script_tag( name: "summary", value: "VMware vRealize Log Insight addresses important and moderate security issues." );
	script_tag( name: "affected", value: "VMware vRealize Log Insight prior to 3.3.2" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)" );
	script_tag( name: "creation_date", value: "2016-06-10 12:19:55 +0200 (Fri, 10 Jun 2016)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_family( "VMware Local Security Checks" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_vmware_vrealize_log_insight_version.sc" );
	script_mandatory_keys( "vmware/vrealize_log_insight/version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "3.3.2" )){
	fix = "3.3.2 Build 3951163";
}
if(version == "3.3.2"){
	build = get_kb_item( "vmware/vrealize_log_insight/build" );
	if(build && int( build ) > 0){
		if(int( build ) < int( 3951163 )){
			fix = "3.3.2 Build 3951163";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

