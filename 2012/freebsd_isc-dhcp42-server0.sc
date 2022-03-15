if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70757" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2011-4868" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)" );
	script_name( "FreeBSD Ports: isc-dhcp42-server" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: isc-dhcp42-server

CVE-2011-4868
The logging functionality in dhcpd in ISC DHCP before 4.2.3-P2, when
using Dynamic DNS (DDNS) and issuing IPv6 addresses, does not properly
handle the DHCPv6 lease structure, which allows remote attackers to
cause a denial of service (NULL pointer dereference and daemon crash)
via crafted packets related to a lease-status update." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://www.isc.org/software/dhcp/advisories/cve-2011-4868" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/1800886c-3dde-11e1-89b4-001ec9578670.html" );
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
bver = portver( pkg: "isc-dhcp42-server" );
if(!isnull( bver ) && revcomp( a: bver, b: "4.2.3_2" ) < 0){
	txt += "Package isc-dhcp42-server version " + bver + " is installed which is known to be vulnerable.\n";
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

