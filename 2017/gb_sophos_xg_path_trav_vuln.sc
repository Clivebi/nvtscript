CPE = "cpe:/o:sophos:xg_firewall_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106903" );
	script_version( "2020-08-21T08:00:21+0000" );
	script_tag( name: "last_modification", value: "2020-08-21 08:00:21 +0000 (Fri, 21 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-06-23 10:58:06 +0700 (Fri, 23 Jun 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Sophos XG Firewall < 16.05.5 MR5 Path Traversal Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sophos_xg_detect.sc", "gb_sophos_xg_detect_userportal.sc" );
	script_mandatory_keys( "sophos/xg_firewall/detected" );
	script_tag( name: "summary", value: "Sophos XG Firewall is prone to a path traversal vulnerability where a
low privileged user may download arbitrary files or elevate his privileges." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Crafting a download request and adding a path traversal vector to it, an
authenticated user, can use this function to download files that are outside the normal scope of the download
feature (including sensitive files).

In addition, the function can be called from a low privileged user, a user that is logged on to the User Portal.
A combinations of these two vulnerabilities can be used to compromise the integrity of the server, by allowing a
user to elevate his privileges." );
	script_tag( name: "affected", value: "Sophos XG Firewall before version 16.05.5 MR5" );
	script_tag( name: "solution", value: "Update to version 16.05.5 MR5 or later." );
	script_xref( name: "URL", value: "https://blogs.securiteam.com/index.php/archives/3253" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "16.05.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "16.05.5" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

