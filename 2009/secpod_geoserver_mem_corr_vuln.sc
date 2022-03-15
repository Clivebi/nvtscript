if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900946" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-7227" );
	script_name( "GeoServer Memory Corruption Vulnerability" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_geoserver_detect.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "GeoServer/installed" );
	script_tag( name: "impact", value: "Successful attacks may lead to failure to report service exception if the code
  encoding the output calls flush() before having written the full contents to the output." );
	script_tag( name: "affected", value: "GeoServer version before 1.6.1 and 1.7.0-beta1." );
	script_tag( name: "insight", value: "An error exists when PartialBufferOutputStream2 flushes the buffer contents even
  when it is handling an 'in memory buffer', which prevents the reporting of a
  service exception, with unknown impact and attack vectors." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to version 1.6.1 or 1.7.0-beta1 or later." );
	script_tag( name: "summary", value: "This host is installed with GeoServer and is prone to a Memory
  Corruption vulnerability." );
	script_xref( name: "URL", value: "http://jira.codehaus.org/browse/GEOS-1747" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
geoPort = http_get_port( default: 8080 );
geoVer = get_kb_item( "www/" + geoPort + "/GeoServer" );
geoVer = eregmatch( pattern: "^(.+) under (/.*)$", string: geoVer );
if(geoVer[1] != NULL){
	if(version_is_less( version: geoVer[1], test_version: "1.6.1" ) || version_in_range( version: geoVer[1], test_version: "1.7", test_version2: "1.7.0.beta" )){
		security_message( port: geoPort, data: "The target host was found to be vulnerable." );
		exit( 0 );
	}
}
exit( 99 );

