if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105594" );
	script_cve_id( "CVE-2015-3626" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "2021-07-12T08:06:48+0000" );
	script_name( "Fortinet FortiOS Multiple Vulnerabilities (FG-IR-16-003)" );
	script_xref( name: "URL", value: "https://www.fortiguard.com/psirt/FG-IR-16-003" );
	script_xref( name: "URL", value: "http://fortiguard.com/advisory/fortios-open-redirect-vulnerability" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to one the following FortiOS versions:

  5.0 branch: 5.0.13 or later

  5.2 branch: 5.2.4 or later

  5.4 branch: 5.4.0 or later

  4.3 and earlier branches are not affected by this vulnerability." );
	script_tag( name: "summary", value: "FortiOS is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "The following flaws exist:

  - It is possible to inject malicious script through the DHCP HOSTNAME option. The malicious script
  code is injected into the device's `DHCP Monitor` page (System->Monitor->DHCP Monitor) on the
  web-based interface which is accessible by the webui administrators.

  - The FortiOS webui accepts a user-controlled input that specifies a link to an external site, and
  uses that link in a redirect. The redirect input parameter is also prone to a cross site scripting." );
	script_tag( name: "affected", value: "5.0 branch: < 5.0.13, 5.2 branch: < 5.2.4." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-07-12 08:06:48 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "creation_date", value: "2016-04-04 11:42:25 +0200 (Mon, 04 Apr 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "FortiOS Local Security Checks" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "forti/FortiOS/version" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!version = get_kb_item( "forti/FortiOS/version" )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0", test_version2: "5.0.12" )){
	fix = "5.0.13";
}
if(version_in_range( version: version, test_version: "5.2", test_version2: "5.2.3" )){
	fix = "5.2.4";
}
if(fix){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

