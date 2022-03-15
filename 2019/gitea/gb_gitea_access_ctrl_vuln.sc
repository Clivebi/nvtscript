CPE = "cpe:/a:gitea:gitea";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141957" );
	script_version( "2021-09-08T09:01:34+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-05 09:55:39 +0700 (Tue, 05 Feb 2019)" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-1000002" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Gitea < 1.6.3 Improper Access Control Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_gitea_detect.sc" );
	script_mandatory_keys( "gitea/detected" );
	script_tag( name: "summary", value: "Gitea contains a Incorrect Access Control vulnerability in Delete/Edit file
functionality that can result in the attacker deleting files outside the repository he/she has access to. This
attack appears to be exploitable via the attacker must get write access to 'any' repository including self-created
ones." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Gitea version 1.6.2 and prior." );
	script_tag( name: "solution", value: "Update to version 1.6.3 or later." );
	script_xref( name: "URL", value: "https://github.com/go-gitea/gitea/pull/5631" );
	script_xref( name: "URL", value: "https://blog.gitea.io/2019/01/release-of-1.6.3/" );
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
if(version_is_less( version: version, test_version: "1.6.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.6.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

