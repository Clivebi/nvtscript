CPE = "cpe:/a:citrix:xenserver";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105323" );
	script_cve_id( "CVE-2015-5154" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2020-04-02T13:53:24+0000" );
	script_name( "Citrix XenServer Security Update for CVE-2015-5154 (CTX201593)" );
	script_xref( name: "URL", value: "http://support.citrix.com/article/CTX201593" );
	script_tag( name: "vuldetect", value: "Check the installed hotfixes." );
	script_tag( name: "solution", value: "Apply the hotfix referenced in the advisory." );
	script_tag( name: "summary", value: "A security vulnerability has been identified in Citrix XenServer that may allow a malicious administrator
  of an HVM guest VM to compromise the host. This vulnerability affects all currently supported versions of Citrix XenServer up to and including
  Citrix XenServer 6.5 Service Pack 1." );
	script_tag( name: "affected", value: "XenServer 6.5

  XenServer 6.2.0

  XenServer 6.0

  XenServer 6.0.2

  XenServer 6.1.0" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2020-04-02 13:53:24 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2015-08-18 14:36:04 +0200 (Tue, 18 Aug 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Citrix Xenserver Local Security Checks" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
patches["6.5.0"] = make_list( "XS65ESP1008",
	 "XS65E013" );
patches["6.2.0"] = make_list( "XS62ESP1030" );
patches["6.1.0"] = make_list( "XS61E057" );
patches["6.0.2"] = make_list( "XS602E045" );
patches["6.0.0"] = make_list( "XS60E050" );
citrix_xenserver_check_report_is_vulnerable( version: version, hotfixes: hotfixes, patches: patches );
exit( 99 );

