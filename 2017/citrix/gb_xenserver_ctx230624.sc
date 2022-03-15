CPE = "cpe:/a:citrix:xenserver";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140607" );
	script_version( "2020-08-25T06:34:32+0000" );
	script_tag( name: "last_modification", value: "2020-08-25 06:34:32 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-12-18 10:17:20 +0700 (Mon, 18 Dec 2017)" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:M/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Citrix XenServer Security Update (CTX230624)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Citrix Xenserver Local Security Checks" );
	script_dependencies( "gb_xenserver_version.sc" );
	script_mandatory_keys( "xenserver/product_version", "xenserver/patches" );
	script_tag( name: "summary", value: "A security issue has been identified within Citrix XenServer that may allow
  the malicious administrator of a guest VM to cause the host to crash." );
	script_tag( name: "affected", value: "XenServer versions 7.2, and 7.1." );
	script_tag( name: "solution", value: "Apply the hotfix referenced in the advisory." );
	script_tag( name: "vuldetect", value: "Check the installed hotfixes." );
	script_xref( name: "URL", value: "https://support.citrix.com/article/CTX230624" );
	exit( 0 );
}
require("citrix_version_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(!hotfixes = get_kb_item( "xenserver/patches" )){
	exit( 0 );
}
patches = make_array();
patches["7.2.0"] = make_list( "XS72E011" );
patches["7.1.0"] = make_list( "XS71ECU1007" );
citrix_xenserver_check_report_is_vulnerable( version: version, hotfixes: hotfixes, patches: patches );
exit( 99 );

