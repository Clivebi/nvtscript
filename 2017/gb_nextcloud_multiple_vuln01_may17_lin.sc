CPE = "cpe:/a:nextcloud:nextcloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811133" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_cve_id( "CVE-2017-0890", "CVE-2017-0892", "CVE-2017-0894" );
	script_bugtraq_id( 98408, 98441, 98442 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-05-30 16:55:47 +0530 (Tue, 30 May 2017)" );
	script_name( "Nextcloud Multiple Vulnerabilities-01 May17 (Linux)" );
	script_tag( name: "summary", value: "The host is installed with Nextcloud and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An inadequate escaping in the search module.

  - An improper session handling allowed an application specific password without
    permission to the files access to the users file.

  - A logical error which cause disclosure of valid share tokens for public
    calendars." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to write or paste malicious content into the search dialogue, or granting an
  attacker potentially access to publicly shared calendars without knowing the share
  token, or allow an application specific password without permission to the files
  access to the users file." );
	script_tag( name: "affected", value: "Nextcloud Server before 11.0.3 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Nextcloud Server 11.0.3 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://nextcloud.com/security/advisory/?id=nc-sa-2017-007" );
	script_xref( name: "URL", value: "https://nextcloud.com/security/advisory/?id=nc-sa-2017-009" );
	script_xref( name: "URL", value: "https://nextcloud.com/security/advisory/?id=nc-sa-2017-011" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_nextcloud_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "nextcloud/installed", "Host/runs_unixoide" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "11.0.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "11.0.3" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

