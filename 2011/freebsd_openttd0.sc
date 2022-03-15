if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68700" );
	script_version( "$Revision: 14117 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-4168" );
	script_name( "FreeBSD Ports: openttd" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: openttd

CVE-2010-4168
Multiple use-after-free vulnerabilities in OpenTTD 1.0.x before 1.0.5
allow (1) remote attackers to cause a denial of service (invalid write
and daemon crash) by abruptly disconnecting during transmission of the
map from the server, related to network/network_server.cpp, (2) remote
attackers to cause a denial of service (invalid read and daemon crash)
by abruptly disconnecting, related to network/network_server.cpp, and
(3) remote servers to cause a denial of service (invalid read and
application crash) by forcing a disconnection during the join process,
related to network/network.cpp." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://security.openttd.org/en/CVE-2010-4168" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/373e412e-f748-11df-96cd-0015f2db7bde.html" );
	script_tag( name: "summary", value: "The remote host is missing an update to the system
  as announced in the referenced advisory." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-bsd.inc.sc");
vuln = FALSE;
txt = "";
bver = portver( pkg: "openttd" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.0.0" ) >= 0 && revcomp( a: bver, b: "1.0.5" ) < 0){
	txt += "Package openttd version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
if( vuln ){
	security_message( data: txt );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

