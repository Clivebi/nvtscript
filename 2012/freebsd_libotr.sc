if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71841" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-3461" );
	script_version( "$Revision: 14117 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-30 11:34:18 -0400 (Thu, 30 Aug 2012)" );
	script_name( "FreeBSD Ports: libotr" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: libotr

CVE-2012-3461
The (1) otrl_base64_otr_decode function in src/b64.c, (2)
otrl_proto_data_read_flags and (3) otrl_proto_accept_data functions in
src/proto.c, and (4) decode function in toolkit/parse.c in libotr
before 3.2.1 allocates a zero-length buffer when decoding a base64
string, which allows remote attackers to cause a denial of service
(application crash) via a message with the value '?OTR:===.', which
triggers a heap-based buffer overflow." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://lists.cypherpunks.ca/pipermail/otr-dev/2012-July/001347.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/c651c898-e90d-11e1-b230-0024e830109b.html" );
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
bver = portver( pkg: "libotr" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.2.1" ) < 0){
	txt += "Package libotr version " + bver + " is installed which is known to be vulnerable.\\n";
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

