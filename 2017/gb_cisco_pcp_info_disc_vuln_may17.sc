CPE = "cpe:/a:cisco:prime_collaboration_provisioning";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811049" );
	script_version( "2021-09-10T12:01:36+0000" );
	script_cve_id( "CVE-2017-6621" );
	script_bugtraq_id( 98522 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-10 12:01:36 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-08 01:29:00 +0000 (Sat, 08 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-05-23 10:41:56 +0530 (Tue, 23 May 2017)" );
	script_name( "Cisco Prime Collaboration Provisioning Information Disclosure Vulnerability - May17" );
	script_tag( name: "summary", value: "This host is running cisco prime collaboration
  provisioning and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to insufficient protection
  of sensitive data when responding to an HTTP request on the web interface." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  unauthenticated, remote attacker to access sensitive data. The attacker could
  use this information to conduct additional reconnaissance attacks." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "affected", value: "Cisco Prime Collaboration Provisioning
  Software Releases 9.0.0, 9.5.0, 10.0.0, 10.5.0, 10.5.1 and 10.6 through 11.5" );
	script_tag( name: "solution", value: "Upgrade to Cisco Prime Collaboration
  Provisioning Software Release 11.6 or 12.1 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc99626" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170517-pcp2" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_pcp_version.sc" );
	script_mandatory_keys( "cisco_pcp/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^((9|10|11)\\.)" )){
	if(( version == "9.0.0" ) || ( version == "9.5.0" ) || ( version == "10.0.0" ) || ( version == "10.5.0" ) || ( version == "10.5.1" ) || ( version == "10.6.0" ) || ( version == "10.6.2" ) || ( version == "11.0.0" ) || ( version == "11.1.0" ) || ( version == "11.5.0" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "11.6 or 12.1" );
		security_message( data: report, port: 0 );
		exit( 0 );
	}
}
exit( 0 );

