CPE = "cpe:/a:juniper:junos_space";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106510" );
	script_version( "2021-09-14T11:01:46+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 11:01:46 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-12 11:36:50 +0700 (Thu, 12 Jan 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_cve_id( "CVE-2016-1762", "CVE-2016-4448", "CVE-2015-5364", "CVE-2016-6515", "CVE-2015-8325", "CVE-2016-1833", "CVE-2016-1834", "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838", "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-5573", "CVE-2016-4449", "CVE-2016-5387", "CVE-2015-5366", "CVE-2016-1907", "CVE-2016-3627", "CVE-2016-3705", "CVE-2016-4447", "CVE-2015-5307", "CVE-2015-8104", "CVE-2016-6662", "CVE-2016-5195", "CVE-2017-2305", "CVE-2017-2306", "CVE-2017-2307", "CVE-2017-2308", "CVE-2017-2309", "CVE-2017-2310", "CVE-2017-2311" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Junos Space Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "JunOS Local Security Checks" );
	script_dependencies( "gb_junos_space_version.sc" );
	script_mandatory_keys( "junos_space/installed" );
	script_tag( name: "summary", value: "Junos Space is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "Junos Space is prone to multiple vulnerabilities in OpenSSH, MySQL, Apache
  HTTP Server, OpenJDK, LibXML, OpenSSL, Linux Kernel and Junos Space itself." );
	script_tag( name: "affected", value: "This issue can affect any product or platform running Junos Space before
  16.1R1." );
	script_tag( name: "solution", value: "Update to version 16.1R1 or later." );
	script_xref( name: "URL", value: "http://kb.juniper.net/JSA10770" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	exit( 0 );
}
require("host_details.inc.sc");
require("junos.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(check_js_version( ver: version, fix: "16.1R1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "16.1R1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );
