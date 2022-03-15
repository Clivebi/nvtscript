CPE = "cpe:/a:citrix:xenserver";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140014" );
	script_cve_id( "CVE-2016-7777" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:N" );
	script_version( "2020-04-02T13:53:24+0000" );
	script_name( "Citrix XenServer Security Update for CVE-2016-7777 (CTX217363)" );
	script_xref( name: "URL", value: "http://support.citrix.com/article/CTX217363" );
	script_tag( name: "vuldetect", value: "Check the installed hotfixes." );
	script_tag( name: "solution", value: "Apply the hotfix referenced in the advisory." );
	script_tag( name: "summary", value: "A security vulnerability has been identified in
  Citrix XenServer that may allow malicious user code within an HVM guest VM to read
  or modify the contents of certain registers belonging to other tasks within that same guest VM." );
	script_tag( name: "affected", value: "This vulnerability affects all currently supported
  versions of Citrix XenServer up to and including Citrix XenServer 7.0." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2020-04-02 13:53:24 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2016-10-25 10:24:27 +0200 (Tue, 25 Oct 2016)" );
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
patches["7.0.0"] = make_list( "XS70E014" );
patches["6.5.0"] = make_list( "XS65ESP1039" );
patches["6.2.0"] = make_list( "XS62ESP1050" );
patches["6.0.2"] = make_list( "XS602ECC035" );
citrix_xenserver_check_report_is_vulnerable( version: version, hotfixes: hotfixes, patches: patches );
exit( 99 );

