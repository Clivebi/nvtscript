CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809771" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_cve_id( "CVE-2016-9207" );
	script_bugtraq_id( 94797 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-22 21:11:00 +0000 (Thu, 22 Dec 2016)" );
	script_tag( name: "creation_date", value: "2016-12-23 16:17:36 +0530 (Fri, 23 Dec 2016)" );
	script_name( "Cisco Video Communications Server 'HTTP Traffic Server' Security Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host is running Cisco TelePresence
  Video Communication Server and is prone to security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to insufficient access
  control for TCP traffic passed through the Cisco Expressway." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to initiate TCP connections to arbitrary hosts, and enumerate hosts and
  services of arbitrary hosts, as well as degrade performance through the Cisco
  Expressway." );
	script_tag( name: "affected", value: "Cisco TelePresence Video Communication
  Server (VCS) X8.7.2 and X8.8.3" );
	script_tag( name: "solution", value: "Upgrade to Cisco TelePresence Video Communication
  Server (VCS) X8.9 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc10834" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161207-expressway" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_vcs_detect.sc", "gb_cisco_vcs_ssh_detect.sc" );
	script_mandatory_keys( "cisco_vcs/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "8.7.2" ) || version_is_equal( version: version, test_version: "8.8.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.9" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

