if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800185" );
	script_version( "$Revision: 14326 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)" );
	script_cve_id( "CVE-2010-3495" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "Zope Object Database ZEO Server Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41755" );
	script_xref( name: "URL", value: "https://bugs.launchpad.net/zodb/+bug/135108" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2010/09/24/3" );
	script_xref( name: "URL", value: "http://launchpadlibrarian.net/10338640/patch.diff" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 8090, 8100 );
	script_tag( name: "impact", value: "Successful exploitation will let the remote unauthenticated attackers to
  cause a denial of service." );
	script_tag( name: "affected", value: "Zope Object Database (ZODB) before 3.10.0" );
	script_tag( name: "insight", value: "The flaw is caused by input validation error in file 'ZEO/StorageServer.py'
  in 'notifyConnected()' function, when an unexpected value of None for the
  address or an ECONNABORTED, EAGAIN, or EWOULDBLOCK error encountered." );
	script_tag( name: "summary", value: "This host is running Zope Object Database and is prone to denial of service
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to version of Zope Object Database (ZODB) 3.10.0 or later" );
	script_xref( name: "URL", value: "http://www.zodb.org/" );
	exit( 0 );
}
zodbPort = 8090;
if(!get_port_state( zodbPort )){
	zodbPort = 8100;
	if(!get_port_state( zodbPort )){
		exit( 0 );
	}
}
soc = open_sock_tcp( zodbPort );
if(!soc){
	exit( 0 );
}
close( soc );
sleep( 5 );
soc = open_sock_tcp( zodbPort );
if(!soc){
	security_message( zodbPort );
	exit( 0 );
}
close( soc );

