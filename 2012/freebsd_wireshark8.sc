if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71872" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-3548" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-09-07 11:47:17 -0400 (Fri, 07 Sep 2012)" );
	script_name( "FreeBSD Ports: wireshark" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  wireshark
   wireshark-lite
   tshark
   tshark-lite

CVE-2012-3548
The dissect_drda function in epan/dissectors/packet-drda.c in
Wireshark 1.6.x through 1.6.10 and 1.8.x through 1.8.2 allows remote
attackers to cause a denial of service (infinite loop and CPU
consumption) via a small value for a certain length field in a capture
file." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=849926" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/5415f1b3-f33d-11e1-8bd8-0022156e8794.html" );
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
bver = portver( pkg: "wireshark" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.5" ) >= 0 && revcomp( a: bver, b: "1.8.2_1" ) < 0){
	txt += "Package wireshark version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "wireshark-lite" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.5" ) >= 0 && revcomp( a: bver, b: "1.8.2_1" ) < 0){
	txt += "Package wireshark-lite version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "tshark" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.5" ) >= 0 && revcomp( a: bver, b: "1.8.2_1" ) < 0){
	txt += "Package tshark version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "tshark-lite" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.5" ) >= 0 && revcomp( a: bver, b: "1.8.2_1" ) < 0){
	txt += "Package tshark-lite version " + bver + " is installed which is known to be vulnerable.\\n";
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

