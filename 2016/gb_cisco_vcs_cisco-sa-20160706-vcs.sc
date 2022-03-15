CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107025" );
	script_cve_id( "CVE-2016-1444" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_name( "Cisco TelePresence Video Communication Server (VCS) Authentication Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-20160706-vcs.html" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160706-vcs" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-27 18:33:00 +0000 (Thu, 27 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-07-11 16:46:52 +0200 (Mon, 11 Jul 2016)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_vcs_detect.sc", "gb_cisco_vcs_ssh_detect.sc" );
	script_mandatory_keys( "cisco_vcs/installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow an unauthenticated, remote attacker to
  bypass authentication and access internal HTTP system resources." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to lack of proper input validation of a trusted
  certificate." );
	script_tag( name: "solution", value: "Updates are available.The advisory is available at the references." );
	script_tag( name: "summary", value: "This host is running Cisco TelePresence Video Communication Server and is
  prone to Authentication Bypass Vulnerability." );
	script_tag( name: "affected", value: "Cisco TelePresence Video Communication Server (VCS) X8.1 through X8.7 and
  Expressway X8.1 through X8.6." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.1", test_version2: "8.7.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "See advisory" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

