if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105408" );
	script_cve_id( "CVE-2015-7753", "CVE-2014-0429", "CVE-2014-0456", "CVE-2014-0460", "CVE-2014-0453", "CVE-2015-0975", "CVE-2015-3209", "CVE-2014-1568", "CVE-2013-2249", "CVE-2013-6438", "CVE-2014-0098", "CVE-2014-6491", "CVE-2014-6500", "CVE-2015-0501", "CVE-2014-6478", "CVE-2014-6494", "CVE-2014-6495", "CVE-2014-6496", "CVE-2014-6559", "CVE-2015-2620", "CVE-2013-5908" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_name( "Multiple Vulnerabilities in Junos Space" );
	script_xref( name: "URL", value: "http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10698&actp=RSS" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "These vulnerabilities include cross site scripting (XSS), SQL injection and command injection vulnerabilities. These vulnerabilities may potentially allow a remote unauthenticated network based attacker with access to Junos Space to execute arbitrary code on Junos Space." );
	script_tag( name: "solution", value: "Update to Junos Space 15.1R1 release or newer" );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been addressed in Junos Space 15.1R1 release." );
	script_tag( name: "affected", value: "Junos Space < 15.1R1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-10-16 20:11:07 +0200 (Fri, 16 Oct 2015)" );
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
fix = "15.1R1";
if(check_js_version( ver: vers, fix: fix )){
	report = "Installed Version: " + vers + "\n" + "Fixed Version:     " + fix;
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

