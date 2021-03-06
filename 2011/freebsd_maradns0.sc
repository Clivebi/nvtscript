if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68957" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0520" );
	script_bugtraq_id( 45966 );
	script_name( "FreeBSD Ports: maradns" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: maradns

CVE-2011-0520
The compress_add_dlabel_points function in dns/Compress.c in MaraDNS
1.4.03, 1.4.05, and probably other versions allows remote attackers to
cause a denial of service (segmentation fault) and possibly execute
arbitrary code via a long DNS hostname with a large number of labels,
which triggers a heap-based buffer overflow." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=610834" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/8015600f-2c80-11e0-9cc1-00163e5bf4f9.html" );
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
bver = portver( pkg: "maradns" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.4.06" ) < 0){
	txt += "Package maradns version " + bver + " is installed which is known to be vulnerable.\n";
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

