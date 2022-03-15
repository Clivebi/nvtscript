CPE = "cpe:/a:apache:hadoop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108173" );
	script_version( "2019-05-10T14:24:23+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2017-06-06 15:24:50 +0200 (Tue, 06 Jun 2017)" );
	script_name( "Apache Hadoop 'Secure Mode' Disabled" );
	script_copyright( "Copyright (c) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_apache_hadoop_detect.sc" );
	script_require_ports( "Services/www", 50070 );
	script_mandatory_keys( "Apache/Hadoop/SecureMode/Disabled" );
	script_tag( name: "summary", value: "The host is installed with Apache Hadoop
  and has 'Secure Mode' disabled." );
	script_tag( name: "vuldetect", value: "Check the status page of Apache Hadoop
  if 'Secure Mode' is enabled or not." );
	script_tag( name: "insight", value: "The flaw exists due to a disabled 'Secure Mode' which
  doesn't require authentication for users." );
	script_tag( name: "impact", value: "Successful exploitation might allow a remote
  attacker to gain unauthenticated access to data saved within this Hadoop instance." );
	script_tag( name: "affected", value: "Apache Hadoop instances with 'Secure Mode' disabled." );
	script_tag( name: "solution", value: "Configure 'Secure Mode' by following the Apache Hadoop documentation." );
	script_xref( name: "URL", value: "https://hadoop.apache.org/docs/stable/hadoop-project-dist/hadoop-common/SecureMode.html" );
	script_xref( name: "URL", value: "https://blog.shodan.io/the-hdfs-juggernaut/" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
secureModeDisabled = get_kb_item( "Apache/Hadoop/SecureMode/" + port + "/Disabled" );
if(secureModeDisabled){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

