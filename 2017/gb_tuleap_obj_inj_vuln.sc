if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113039" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-24 11:04:55 +0200 (Tue, 24 Oct 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-12-27 17:08:00 +0000 (Wed, 27 Dec 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-7411" );
	script_name( "Tuleap < 9.7 Object Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_tuleap_detect.sc" );
	script_mandatory_keys( "tuleap/installed" );
	script_tag( name: "summary", value: "Tuleap version 5.0 through 9.6 allows authenticated attackers to
  execute arbitrary code on the host via an Object Injection vulnerability." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the host." );
	script_tag( name: "insight", value: "The vulnerability exists because this method is using the unserialize()
  function with a value that can be arbitrarily manipulated by a user through the REST API interface. This
  can be exploited to inject arbitrary PHP objects into the application scope, and could allow authenticated
  attackers to execute arbitrary PHP code via specially crafted serialized objects. Successful exploitation
  of this vulnerability requires an user account with permissions to create or access artifacts in a tracker." );
	script_tag( name: "impact", value: "Successful exploitation would allow the attacker to execute arbitrary code on the host." );
	script_tag( name: "affected", value: "Tuleap version 5.0 through 9.6." );
	script_tag( name: "solution", value: "Update to Tuleap version 9.7." );
	script_xref( name: "URL", value: "http://karmainsecurity.com/KIS-2017-02" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2017/10/23/3" );
	exit( 0 );
}
CPE = "cpe:/a:enalean:tuleap";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_greater_equal( version: version, test_version: "5.0" ) && version_is_less( version: version, test_version: "9.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.7" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

