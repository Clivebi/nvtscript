CPE = "cpe:/a:symantec:encryption_desktop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811786" );
	script_version( "2021-09-14T12:01:45+0000" );
	script_cve_id( "CVE-2017-6330" );
	script_bugtraq_id( 100552 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-14 12:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-09-22 11:53:27 +0530 (Fri, 22 Sep 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Symantec Encryption Desktop Denial-of-Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Symantec
  Encryption Desktop and is prone to denial-of-service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to some unspecified error
  within the application." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to cause denial-of-service conditions." );
	script_tag( name: "affected", value: "Symantec Encryption Desktop prior to
  version 10.4.1MP2." );
	script_tag( name: "solution", value: "Upgrade to Symantec Encryption Desktop
  version 10.4.1MP2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20170907_00" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_pgp_desktop_detect_win.sc" );
	script_mandatory_keys( "PGPDesktop_or_EncryptionDesktop/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!symanVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: symanVer, test_version: "10.4.1.7591" )){
	report = report_fixed_ver( installed_version: symanVer, fixed_version: "10.4.1MP2" );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

