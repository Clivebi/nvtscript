if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69601" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0997" );
	script_name( "FreeBSD Ports: isc-dhcp31-client" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  isc-dhcp31-client
   isc-dhcp41-client

CVE-2011-0997
dhclient in ISC DHCP 3.0.x through 4.2.x before 4.2.1-P1, 3.1-ESV
before 3.1-ESV-R1, and 4.1-ESV before 4.1-ESV-R2 allows remote
attackers to execute arbitrary commands via shell metacharacters in a
hostname obtained from a DHCP message, as demonstrated by a hostname
that is provided to dhclient-script." );
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
bver = portver( pkg: "isc-dhcp31-client" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.1.ESV_1,1" ) < 0){
	txt += "Package isc-dhcp31-client version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "isc-dhcp41-client" );
if(!isnull( bver ) && revcomp( a: bver, b: "4.1.e,2" ) < 0){
	txt += "Package isc-dhcp41-client version " + bver + " is installed which is known to be vulnerable.\n";
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

