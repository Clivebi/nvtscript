CPE = "cpe:/a:ipswitch:imail_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811255" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_cve_id( "CVE-2017-12638", "CVE-2017-12639" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-10-10 17:52:00 +0000 (Tue, 10 Oct 2017)" );
	script_tag( name: "creation_date", value: "2017-07-26 12:49:28 +0530 (Wed, 26 Jul 2017)" );
	script_name( "Ipswitch IMail Server SMTPD RCE Vulnerability (ETRE/ETCETERABLUE)" );
	script_tag( name: "summary", value: "This host is running Ipswitch Collaboration
  Suite/IMail Server and is prone to remote code execution." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to some unspecified buffer
  overflow error in the application as disclosed by Shadow Brokers." );
	script_tag( name: "impact", value: "Successfully exploiting this issue will allow
  remote attackers to execute arbitrary code on the target system." );
	script_tag( name: "affected", value: "IMail Server all versions prior to 12.5.6" );
	script_tag( name: "solution", value: "Upgrade to IMail Server version 12.5.6 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://github.com/misterch0c/shadowbroker" );
	script_xref( name: "URL", value: "http://docs.ipswitch.com/_Messaging/IMailServer/v12.5.6/ReleaseNotes/index.htm" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_ipswitch_imail_server_detect.sc" );
	script_mandatory_keys( "Ipswitch/IMail/detected" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!imVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: imVer, test_version: "12.5.6" )){
	report = report_fixed_ver( installed_version: imVer, fixed_version: "12.5.6" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

