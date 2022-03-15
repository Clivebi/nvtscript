CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813441" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_cve_id( "CVE-2018-5751", "CVE-2018-5752", "CVE-2018-5756" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-03 17:09:00 +0000 (Fri, 03 Aug 2018)" );
	script_tag( name: "creation_date", value: "2018-06-19 11:01:29 +0530 (Tue, 19 Jun 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Open-Xchange (OX) AppSuite Multiple Vulnerabilities-01(June18)" );
	script_tag( name: "summary", value: "The host is installed with
  Open-Xchange (OX) AppSuite and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as,

  - Inviting external users to share content creates temporary user accounts to
    handle permissions. Several APIs expose information about user accounts, however
    data of external guests is not meant to be available for others than the sharing
    user and users that got access to the shared content.

  - OX App Suite uses several blacklists to restrict access of external services.
    Those do not cover non-decimal representations of IP addresses and special IPv6
    related addresses. Some libraries accept such values and blacklist fails to
    convert them when checking.

  - OX App Suite tries to look up external mail account configuration using XML files
    for auto-configuration, that are placed at most mail providers hosts. Redirects of
    external HTTP services could be used to access local or internal networks instead,
    when looking up that external account information.

  - OX App Suite can be used to embed external RSS feeds, which are requested using
    HTTP. Redirects of external HTTP services could be used to access local or internal
    networks instead, when looking up that external account information.

  - Permission checks for tasks were incomplete with regards to folder-to-object
    association." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to gain access to sensitive information like guest users, primarily e-mail
  addresses, internal network configuration, open ports and associated services.
  Also an attacker within the same context will be able to add external participants
  to other users appointments and delete other users tasks." );
	script_tag( name: "affected", value: "Open-Xchange OX App Suite before 7.6.3-rev36,
  7.8.x before 7.8.2-rev39, 7.8.3 before 7.8.3-rev44, and 7.8.4 before 7.8.4-rev22" );
	script_tag( name: "solution", value: "Upgrade to Open-Xchange (OX) AppSuite
  version 7.6.3-rev36 or 7.8.2-rev39 or 7.8.3-rev44 or 7.8.4-rev22 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/44881" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2018/Jun/23" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/148118" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ox_app_suite_detect.sc" );
	script_mandatory_keys( "open_xchange_appsuite/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!oxPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: oxPort, exit_no_version: TRUE )){
	exit( 0 );
}
oxVer = infos["version"];
path = infos["location"];
oxRev = get_kb_item( "open_xchange_appsuite/" + oxPort + "/revision" );
if(!oxRev){
	exit( 0 );
}
oxVer = oxVer + "." + oxRev;
if( version_is_less( version: oxVer, test_version: "7.6.3.36" ) ){
	fix = "7.6.3-rev36";
}
else {
	if( version_in_range( version: oxVer, test_version: "7.8.2", test_version2: "7.8.2.38" ) ){
		fix = "7.8.2-rev39";
	}
	else {
		if( version_in_range( version: oxVer, test_version: "7.8.3", test_version2: "7.8.3.43" ) ){
			fix = "7.8.3-rev44";
		}
		else {
			if(version_in_range( version: oxVer, test_version: "7.8.4", test_version2: "7.8.4.21" )){
				fix = "7.8.4-rev22";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: oxVer, fixed_version: fix, install_path: path );
	security_message( data: report, port: oxPort );
	exit( 0 );
}
exit( 0 );

