if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808093" );
	script_version( "2020-04-02T11:36:28+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-04-02 11:36:28 +0000 (Thu, 02 Apr 2020)" );
	script_tag( name: "creation_date", value: "2016-06-21 12:44:48 +0530 (Tue, 21 Jun 2016)" );
	script_name( "Elasticsearch Logstash Version Detection" );
	script_tag( name: "summary", value: "Check for the version of Elasticsearch
  Logstash.

  This script sends an HTTP GET request and tries to get the version of
  Elasticsearch Logstash from the response.

  This plugin has been deprecated and merged into the NVT 'Elasticsearch and Logstash Detection'
  (OID: 1.3.6.1.4.1.25623.1.0.105031)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

