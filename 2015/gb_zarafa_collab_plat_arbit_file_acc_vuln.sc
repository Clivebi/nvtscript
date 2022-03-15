CPE = "cpe:/a:zarafa:zarafa_collaboration_platform";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805708" );
	script_version( "2020-11-12T09:50:32+0000" );
	script_tag( name: "cvss_base", value: "6.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-11-12 09:50:32 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-07-03 15:19:25 +0530 (Fri, 03 Jul 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_cve_id( "CVE-2015-3436" );
	script_name( "Zarafa Collaboration Platform Arbitrary File Access Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Zarafa
  Collaboration Platform and is prone to an arbitrary file access
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to
  'provider/server/ECServer.cpp' allows local users to write to arbitrary
  files via a symlink attack on '/tmp/zarafa-upgrade-lock'" );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to retrieve or delete arbitrary files, which may aid in further
  attacks." );
	script_tag( name: "affected", value: "Zarafa Collaboration Platform (ZCP)
  before 7.1.13 and 7.2.x before 7.2.1" );
	script_tag( name: "solution", value: "Upgrade to 7.1.13 or 7.2.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://jira.zarafa.com/browse/ZCP-13282" );
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2015-June/159497.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zarafa_webapp_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "zarafa_zcp/installed" );
	script_xref( name: "URL", value: "https://www.zarafa.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!zcpPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!zcpVer = get_app_version( cpe: CPE, port: zcpPort )){
	exit( 0 );
}
if(version_is_less( version: zcpVer, test_version: "7.1.13" )){
	fix = "7.1.13";
	vuln = TRUE;
}
if(IsMatchRegexp( zcpVer, "^7\\.2" )){
	if(version_is_less( version: zcpVer, test_version: "7.2.1" )){
		fix = "7.2.1";
		vuln = TRUE;
	}
}
if(vuln){
	report = "Installed Version: " + zcpVer + "\n" + "Fixed Version:     " + fix + "\n";
	security_message( data: report, port: zcpPort );
	exit( 0 );
}
exit( 99 );

