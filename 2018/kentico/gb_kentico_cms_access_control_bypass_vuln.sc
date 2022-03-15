if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112248" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-20 14:34:43 +0100 (Tue, 20 Feb 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-17736" );
	script_name( "Kentico CMS < 9.0.51 & < 10.0.48 Access Control Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_kentico_cms_detect.sc" );
	script_mandatory_keys( "kentico_cms/detected" );
	script_tag( name: "summary", value: "Kentico CMS is prone to an access control bypass vulnerability." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Kentico CMS is vulnerable to an access control bypass as it fails to properly
restrict access the installation wizard. It is possible for anunauthenticated user to gain access to these pages
and perform actions such as installing a new starter site or obtaining access to the \"New  site wizard\",
which automatically authenticates as the Global Administrator." );
	script_tag( name: "impact", value: "An unauthenticated attacker may leverage this issue to gain Global Administrator access
to a Kentico installation. From there it is possible to perform administrative actions, install news sites or potentially obtain remote code execution." );
	script_tag( name: "affected", value: "Kentico CMS versions 9 up to 9.0.51 and version 10 up to 10.0.48." );
	script_tag( name: "solution", value: "Upgrade Kentico CMS to version 9.0.51 or 10.0.48." );
	script_xref( name: "URL", value: "https://blog.hivint.com/advisory-access-control-bypass-in-kentico-cms-cve-2017-17736-49e1e43ae55b" );
	exit( 0 );
}
CPE = "cpe:/a:kentico:cms";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if( IsMatchRegexp( version, "^9\\.0" ) ){
	if(version_is_less( version: version, test_version: "9.0.51" )){
		vuln = TRUE;
		fix = "9.0.51";
	}
}
else {
	if(IsMatchRegexp( version, "^10\\.0" )){
		if(version_is_less( version: version, test_version: "10.0.48" )){
			vuln = TRUE;
			fix = "10.0.48";
		}
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

