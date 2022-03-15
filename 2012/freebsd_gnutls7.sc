if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71294" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-1573" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)" );
	script_name( "FreeBSD Ports: gnutls" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  gnutls
   gnutls-devel

CVE-2012-1573
gnutls_cipher.c in libgnutls in GnuTLS before 2.12.17 and 3.x before
3.0.15 does not properly handle data encrypted with a block cipher,
which allows remote attackers to cause a denial of service (heap
memory corruption and application crash) via a crafted record, as
demonstrated by a crafted GenericBlockCipher structure." );
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
bver = portver( pkg: "gnutls" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.12.18" ) < 0){
	txt += "Package gnutls version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "gnutls-devel" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.99" ) > 0 && revcomp( a: bver, b: "3.0.15" ) < 0){
	txt += "Package gnutls-devel version " + bver + " is installed which is known to be vulnerable.\\n";
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

