if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.104155" );
	script_version( "2020-10-27T15:01:28+0000" );
	script_tag( name: "last_modification", value: "2020-10-27 15:01:28 +0000 (Tue, 27 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Nmap NSE net: rmi-dumpregistry" );
	script_category( ACT_INIT );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH" );
	script_family( "Nmap NSE net" );
	script_tag( name: "summary", value: "Connects to a remote RMI registry and attempts to dump all of its objects.

First it tries to determine the names of all objects bound in the registry, and then it tries to
determine information about the objects, such as the class names of the superclasses and
interfaces. This may, depending on what the registry is used for, give valuable information about
the service. E.g, if the app uses JMX (Java Management eXtensions), you should see an object called
'jmxconnector' on it.

It also gives information about where the objects are located, (marked with @<ip>:port in the
output).

Some apps give away the classpath, which this scripts catches in so-called 'Custom data'." );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

