if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113085" );
	script_version( "2021-05-26T06:00:13+0200" );
	script_tag( name: "last_modification", value: "2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-01-17 15:45:55 +0100 (Wed, 17 Jan 2018)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 20:01:00 +0000 (Tue, 09 Oct 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-8802" );
	script_name( "Zimbra ZCS XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_zimbra_admin_console_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "zimbra_web/installed" );
	script_tag( name: "summary", value: "XSS Vulnerability in Zimbra Collaboration Suite (ZCS) before 8.8.0 Beta 2." );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Remote attackers can target the vulnerability by sending an Email with XSS payload (e.g. JavaScript)
  in its body. In case the recipient selects the email in the Zimbra client, and accesses the 'Show
  Snippet' functionality using the 'Q' shortcut, the XSS payload is executed in the context of the
  recipient's Zimbra client." );
	script_tag( name: "impact", value: "Beside others, the malicious payload could
  compromise the confidentility, integrity as well as availability of the victim's emails. Also it
  could be possible to change Zimbra settings of the corresponding victim." );
	script_tag( name: "affected", value: "ZCS before 8.8.0 Beta 2" );
	script_tag( name: "solution", value: "Update to ZCS 8.8.0 Beta 2" );
	script_xref( name: "URL", value: "https://www.compass-security.com/fileadmin/Datein/Research/Advisories/CSNC-2018-001_zimbra_stored_xss.txt" );
	script_xref( name: "URL", value: "https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories" );
	exit( 0 );
}
CPE = "cpe:/a:zimbra:zimbra_collaboration_suite";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "8.8.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.8.0 Beta 2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

