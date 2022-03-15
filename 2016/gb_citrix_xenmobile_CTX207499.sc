CPE = "cpe:/a:citrix:xenmobile_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105580" );
	script_cve_id( "CVE-2016-2789" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_name( "Persistent Cross-Site Scripting Vulnerability in Citrix XenMobile Server 10.x Web User Interface" );
	script_xref( name: "URL", value: "http://support.citrix.com/article/CTX207499" );
	script_tag( name: "impact", value: "This vulnerability could potentially be used to execute malicious client-side script in the same context as legitimate content from the web server, if this vulnerability is used to execute script in the browser of an authenticated administrator then the script may be able to gain access to the administrator's session or other potentially sensitive information." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to Citrix XenMobile 10.3 Rolling Patch 1/Citrix XenMobile 10.1 Rolling Patch 4 or newer." );
	script_tag( name: "summary", value: "A Cross-Site Scripting (XSS) vulnerability has been identified in XenMobile Server 10.x." );
	script_tag( name: "affected", value: "All versions of Citrix XenMobile Server 10.0

Citrix XenMobile Server 10.1 earlier than Rolling Patch 4

Citrix XenMobile Server 10.3 earlier than Rolling Patch 1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-03 03:25:00 +0000 (Sat, 03 Dec 2016)" );
	script_tag( name: "creation_date", value: "2016-03-18 11:15:00 +0100 (Fri, 18 Mar 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_citrix_xenmobile_detect.sc" );
	script_require_ports( "Services/www", 80, 443, 8443 );
	script_mandatory_keys( "citrix_xenmobile_server/patch_release", "citrix_xenmobile_server/version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
patch = get_kb_item( "citrix_xenmobile_server/patch_release" );
if(IsMatchRegexp( vers, "^10\\.0" )){
	fix = "10.1 Rolling Patch 4";
}
if(IsMatchRegexp( vers, "^10\\.1" )){
	if(patch){
		if( patch == "no_patches" ) {
			fix = "10.1 Rolling Patch 4";
		}
		else {
			if(version_is_less( version: patch, test_version: "10.1.0.68170" )){
				fix = "10.1 Rolling Patch 4";
			}
		}
	}
}
if(IsMatchRegexp( vers, "^10\\.3" )){
	if(patch){
		if( patch == "no_patches" ) {
			fix = "10.3 Rolling Patch 1";
		}
		else {
			if(version_is_less( version: patch, test_version: "10.3.0.10004" )){
				fix = "10.3 Rolling Patch 1";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: "none", installed_patch: patch, fixed_patch: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

