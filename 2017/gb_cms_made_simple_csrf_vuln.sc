CPE = "cpe:/a:cmsmadesimple:cms_made_simple";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106538" );
	script_version( "2021-09-09T12:15:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 12:15:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-24 09:44:44 +0700 (Tue, 24 Jan 2017)" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-27 16:48:00 +0000 (Fri, 27 Jan 2017)" );
	script_cve_id( "CVE-2016-7904" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "CMS Made Simple CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cms_made_simple_detect.sc" );
	script_mandatory_keys( "cmsmadesimple/installed" );
	script_tag( name: "summary", value: "CMS Made Simple is prone to a CSRF vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Cross-site request forgery (CSRF) vulnerability allows remote attackers to
hijack the authentication of administrators for requests that create accounts via an admin/adduser.php request." );
	script_tag( name: "affected", value: "CMS Made Simple version 2.1.5 and prior." );
	script_tag( name: "solution", value: "Upgrade to version 2.1.6 or later" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2017/01/16/1" );
	script_xref( name: "URL", value: "http://dev.cmsmadesimple.org/project/changelog/5392" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.1.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.6" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

