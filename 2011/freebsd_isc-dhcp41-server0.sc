if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68958" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2011-0413" );
	script_name( "FreeBSD Ports: isc-dhcp41-server" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: isc-dhcp41-server

CVE-2011-0413
The DHCPv6 server in ISC DHCP 4.0.x and 4.1.x before 4.1.2-P1, 4.0-ESV
and 4.1-ESV before 4.1-ESV-R1, and 4.2.x before 4.2.1b1 allows remote
attackers to cause a denial of service (assertion failure and daemon
crash) by sending a message over IPv6 for a declined and abandoned
address." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.isc.org/software/dhcp/advisories/cve-2011-0413" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/686084" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/dc9f8335-2b3b-11e0-a91b-00e0815b8da8.html" );
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
bver = portver( pkg: "isc-dhcp41-server" );
if(!isnull( bver ) && revcomp( a: bver, b: "4.1.2,1" ) <= 0){
	txt += "Package isc-dhcp41-server version " + bver + " is installed which is known to be vulnerable.\n";
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

