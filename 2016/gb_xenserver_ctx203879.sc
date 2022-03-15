CPE = "cpe:/a:citrix:xenserver";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105528" );
	script_cve_id( "CVE-2015-8554", "CVE-2015-8104", "CVE-2015-8555" );
	script_tag( name: "cvss_base", value: "6.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:S/C:C/I:C/A:C" );
	script_version( "2020-04-02T13:53:24+0000" );
	script_name( "Citrix XenServer Multiple Security Updates (CTX203879)" );
	script_xref( name: "URL", value: "http://support.citrix.com/article/CTX203879" );
	script_tag( name: "vuldetect", value: "Check the installed hotfixes." );
	script_tag( name: "solution", value: "Apply the hotfix referenced in the advisory." );
	script_tag( name: "summary", value: "A number of security vulnerabilities have been
  identified in Citrix XenServer that could, in certain configurations, allow a
  malicious administrator of a guest VM to compromise the host or obtain potentially
  sensitive information from other guest VMs. In addition, a vulnerability has been
  identified that would allow certain applications running on a guest to cause that guest to crash." );
	script_tag( name: "affected", value: "Citrix XenServer up to and including Citrix XenServer 6.5 Service Pack 1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2020-04-02 13:53:24 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2016-01-26 12:17:18 +0100 (Tue, 26 Jan 2016)" );
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
patches["6.5.0"] = make_list( "XS65ESP1020",
	 "XS65ESP1021" );
patches["6.2.0"] = make_list( "XS62ESP1037",
	 "XS62ESP1038" );
patches["6.1.0"] = make_list( "XS61E063",
	 "XS61E064" );
patches["6.0.2"] = make_list( "XS602E050",
	 "XS602ECC026",
	 "XS602ECC027" );
patches["6.0.0"] = make_list( "XS60E055",
	 "XS60E056" );
citrix_xenserver_check_report_is_vulnerable( version: version, hotfixes: hotfixes, patches: patches );
exit( 99 );

