if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71542" );
	script_tag( name: "cvss_base", value: "2.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-1820" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)" );
	script_name( "FreeBSD Ports: quagga" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  quagga
   quagga-re

CVE-2012-1820
The bgp_capability_orf function in bgpd in Quagga 0.99.20.1 and
earlier allows remote attackers to cause a denial of service
(assertion failure and daemon exit) by leveraging a BGP peering
relationship and sending a malformed Outbound Route Filtering (ORF)
capability TLV in an OPEN message." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/962587" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/1e14d46f-af1f-11e1-b242-00215af774f0.html" );
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
bver = portver( pkg: "quagga" );
if(!isnull( bver ) && revcomp( a: bver, b: "0.99.20.1" ) <= 0){
	txt += "Package quagga version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "quagga-re" );
if(!isnull( bver ) && revcomp( a: bver, b: "0.99.17.10" ) < 0){
	txt += "Package quagga-re version " + bver + " is installed which is known to be vulnerable.\\n";
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

