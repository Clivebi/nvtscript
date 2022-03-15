CPE = "cpe:/a:apache:activemq";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142371" );
	script_version( "2021-09-02T13:01:30+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-05-06 11:15:16 +0000 (Mon, 06 May 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-06 12:56:00 +0000 (Tue, 06 Apr 2021)" );
	script_cve_id( "CVE-2019-0222" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Apache ActiveMQ < 5.15.9 DoS Vulnerability - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_apache_activemq_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/activemq/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "In Apache ActiveMQ unmarshalling corrupt MQTT frame can lead to broker Out of
  Memory exception making it unresponsive." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Apache ActiveMQ 5.0.0 to 5.15.8." );
	script_tag( name: "solution", value: "Upgrade to version 5.15.9 or later." );
	script_xref( name: "URL", value: "http://activemq.apache.org/security-advisories.data/CVE-2019-0222-announcement.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.15.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.15.9" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

