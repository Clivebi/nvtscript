if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113804" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-03-18 10:48:12 +0000 (Thu, 18 Mar 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-23 12:34:00 +0000 (Tue, 23 Mar 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-13924" );
	script_name( "Apache Ambari <= 2.6.2.2 Directory Traversal Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_ambari_detect.sc" );
	script_mandatory_keys( "Apache/Ambari/Installed" );
	script_tag( name: "summary", value: "Apache Ambari is prone to a directory traversal vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker
  to read sensitive information." );
	script_tag( name: "affected", value: "Apache Ambari through version 2.6.2.2." );
	script_tag( name: "solution", value: "Update to version 2.7.0 or later." );
	script_xref( name: "URL", value: "https://mail-archives.apache.org/mod_mbox/ambari-user/202102.mbox/%3CCAEJYuxEQZ_aPwJdAaSxPu-Dva%3Dhc7zZUx3-pzBORbd23g%2BGH1A%40mail.gmail.com%3E" );
	exit( 0 );
}
CPE = "cpe:/a:apache:ambari";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.7.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.7.0", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

