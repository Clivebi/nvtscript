if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70596" );
	script_tag( name: "creation_date", value: "2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_cve_id( "CVE-2011-4539" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "$Revision: 11762 $" );
	script_name( "FreeBSD Ports: isc-dhcp42-server" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  isc-dhcp42-server
   isc-dhcp41-server

CVE-2011-4539
dhcpd in ISC DHCP 4.x before 4.2.3-P1 and 4.1-ESV before 4.1-ESV-R4
does not properly handle regular expressions in dhcpd.conf, which
allows remote attackers to cause a denial of service (daemon crash)
via a crafted request packet." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
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
if(!isnull( bver ) && revcomp( a: bver, b: "4.2.3_1" ) < 0){
	txt += "Package isc-dhcp42-server version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "isc-dhcp41-server" );
if(!isnull( bver ) && revcomp( a: bver, b: "4.1.e_3,2" ) < 0){
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

