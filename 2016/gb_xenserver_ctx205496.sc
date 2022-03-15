CPE = "cpe:/a:citrix:xenserver";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105527" );
	script_cve_id( "CVE-2016-1571" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:C" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_name( "Citrix XenServer Security Update for CVE-2016-1571 (CTX205496)" );
	script_xref( name: "URL", value: "http://support.citrix.com/article/CTX205496" );
	script_tag( name: "vuldetect", value: "Check the installed hotfixes." );
	script_tag( name: "solution", value: "Apply the hotfix referenced in the advisory." );
	script_tag( name: "summary", value: "A security vulnerability has been identified in
  Citrix XenServer that could, if exploited, allow a malicious administrator of a guest
  VM to crash the host in certain deployments" );
	script_tag( name: "affected", value: "Citrix XenServer up to and including Citrix XenServer 6.5 Service Pack 1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:26:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-01-26 12:16:17 +0100 (Tue, 26 Jan 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Citrix Xenserver Local Security Checks" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_xenserver_version.sc" );
	script_mandatory_keys( "xenserver/product_version", "xenserver/patches" );
	exit( 0 );
}
require("citrix_version_func.inc.sc");
require("host_details.inc.sc");
require("list_array_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(!hotfixes = get_kb_item( "xenserver/patches" )){
	exit( 0 );
}
patches = make_array();
patches["6.5.0"] = make_list( "XS65ESP1023" );
patches["6.2.0"] = make_list( "XS62ESP1040" );
patches["6.1.0"] = make_list( "XS61E066" );
patches["6.0.2"] = make_list( "XS602E052",
	 "XS602ECC029" );
patches["6.0.0"] = make_list( "XS60E058" );
citrix_xenserver_check_report_is_vulnerable( version: version, hotfixes: hotfixes, patches: patches );
exit( 99 );

