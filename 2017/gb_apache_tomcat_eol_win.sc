CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108134" );
	script_version( "2021-02-16T13:37:32+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-02-16 13:37:32 +0000 (Tue, 16 Feb 2021)" );
	script_tag( name: "creation_date", value: "2017-02-27 11:48:20 +0100 (Mon, 27 Feb 2017)" );
	script_name( "Apache Tomcat End of Life (EOL) Detection (Windows)" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/tomcat-80-eol.html" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/tomcat-60-eol.html" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/tomcat-55-eol.html" );
	script_xref( name: "URL", value: "https://en.wikipedia.org/wiki/Apache_Tomcat#Releases" );
	script_xref( name: "URL", value: "https://tomcat.apache.org/whichversion.html" );
	script_tag( name: "summary", value: "The Apache Tomcat version on the remote host has reached
  the End of Life (EOL) and should not be used anymore." );
	script_tag( name: "impact", value: "An EOL version of Apache Tomcat is not receiving any security
  updates from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker
  to compromise the security of this host." );
	script_tag( name: "solution", value: "Update the Apache Tomcat version on the remote host to a
  still supported version." );
	script_tag( name: "vuldetect", value: "Checks if an EOL version is present on the target host." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("products_eol.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
if(ret = product_reached_eol( cpe: CPE, version: version )){
	report = build_eol_message( name: "Apache Tomcat", cpe: CPE, version: version, location: infos["location"], eol_version: ret["eol_version"], eol_date: ret["eol_date"], eol_type: "prod" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

