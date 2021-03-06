CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806624" );
	script_version( "$Revision: 13803 $" );
	script_cve_id( "CVE-2015-7450" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2015-11-17 17:28:17 +0530 (Tue, 17 Nov 2015)" );
	script_name( "IBM WebSphere Application Server Unserialize Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	script_xref( name: "URL", value: "https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/#websphere" );
	script_tag( name: "summary", value: "The host is running IBM WebSphere
  Application Server and is prone to unserialize vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to presence
  of a deserialization error." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  8.5.5.7 and prior." );
	script_tag( name: "solution", value: "No known solution was made available for
  at least one year since the disclosure of this vulnerability. Likely none will be
  provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by
  another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!webVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: webVer, test_version: "8.5.5.7" )){
	report = report_fixed_ver( installed_version: webVer, fixed_version: "WillNotFix" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

