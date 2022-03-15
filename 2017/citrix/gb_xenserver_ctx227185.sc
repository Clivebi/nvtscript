CPE = "cpe:/a:citrix:xenserver";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140371" );
	script_version( "2021-09-14T13:01:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 13:01:54 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-15 10:57:19 +0700 (Fri, 15 Sep 2017)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-19 10:29:00 +0000 (Fri, 19 Oct 2018)" );
	script_cve_id( "CVE-2017-14316", "CVE-2017-14318", "CVE-2017-14319" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Citrix XenServer Multiple Security Updates (CTX227185)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Citrix Xenserver Local Security Checks" );
	script_dependencies( "gb_xenserver_version.sc" );
	script_mandatory_keys( "xenserver/product_version", "xenserver/patches" );
	script_tag( name: "summary", value: "A number of security vulnerabilities have been identified in Citrix
  XenServer that may allow a malicious administrator of a guest VM to compromise the host." );
	script_tag( name: "insight", value: "The following vulnerabilities have been addressed:

  - CVE-2017-14316: (High) Missing NUMA node parameter verification.

  - CVE-2017-14318: (Medium) Missing check for grant table.

  - CVE-2017-14319: (High) insufficient grant unmapping checks for x86 PV guests." );
	script_tag( name: "affected", value: "XenServer versions 7.2, 7.1, 7.0, 6.5, 6.2.0, 6.0.2." );
	script_tag( name: "solution", value: "Apply the hotfix referenced in the advisory." );
	script_tag( name: "vuldetect", value: "Check the installed hotfixes." );
	script_xref( name: "URL", value: "https://support.citrix.com/article/CTX227185" );
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
patches["7.2.0"] = make_list( "XS72E006" );
patches["7.1.0"] = make_list( "XS71E015" );
patches["7.0.0"] = make_list( "XS70E044" );
patches["6.5.0"] = make_list( "XS65ESP1061" );
patches["6.2.0"] = make_list( "XS62ESP1064" );
patches["6.0.2"] = make_list( "XS602ECC048" );
citrix_xenserver_check_report_is_vulnerable( version: version, hotfixes: hotfixes, patches: patches );
exit( 99 );

