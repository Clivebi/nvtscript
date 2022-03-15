if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105413" );
	script_cve_id( "CVE-2014-0460", "CVE-2014-0423", "CVE-2014-4264", "CVE-2014-0411", "CVE-2014-0453", "CVE-2014-4244", "CVE-2014-4263", "CVE-2012-2110", "CVE-2012-2333", "CVE-2014-0224", "CVE-2011-4576", "CVE-2011-4619", "CVE-2012-0884", "CVE-2013-0166", "CVE-2011-4109", "CVE-2013-0169", "CVE-2013-5908" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_name( "Junos Space: Multiple vulnerabilities resolved by third party software upgrades" );
	script_xref( name: "URL", value: "http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10659" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Oracle Java runtime 1.7.0 update_45 was upgraded to 1.7.0 update_65. OpenSSL CentOS package was upgraded from 0.9.8e-20 to 0.9.8e-27.el5." );
	script_tag( name: "solution", value: "These issues are fixed in Junos Space 14.1R1 and all subsequent releases." );
	script_tag( name: "summary", value: "Junos Space release 14.1R1 addresses multiple vulnerabilities in prior releases with updated third party software components." );
	script_tag( name: "affected", value: "Junos Space and JA1500, JA2500 (Junos Space Appliance) with Junos Space 13.3 and earlier releases." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-10-19 13:03:28 +0200 (Mon, 19 Oct 2015)" );
	script_category( ACT_GATHER_INFO );
	script_family( "JunOS Local Security Checks" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_junos_space_version.sc" );
	script_mandatory_keys( "junos_space/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("junos.inc.sc");
cpe = "cpe:/a:juniper:junos_space";
if(!vers = get_app_version( cpe: cpe )){
	exit( 0 );
}
fix = "14.1R1";
if(check_js_version( ver: vers, fix: fix )){
	report = "Installed Version: " + vers + "\n" + "Fixed Version:     " + fix;
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

