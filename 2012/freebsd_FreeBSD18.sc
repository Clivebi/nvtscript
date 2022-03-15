if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71532" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2012-2143" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)" );
	script_name( "FreeBSD Ports: FreeBSD" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: FreeBSD

CVE-2012-2143
The crypt_des (aka DES-based crypt) function in FreeBSD before
9.0-RELEASE-p2, as used in PHP, PostgreSQL, and other products, does
not process the complete cleartext password if this password contains
a 0x80 character, which makes it easier for context-dependent
attackers to obtain access via an authentication attempt with an
initial substring of the intended password, as demonstrated by a
Unicode password." );
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
bver = portver( pkg: "FreeBSD" );
if(!isnull( bver ) && revcomp( a: bver, b: "7.4" ) >= 0 && revcomp( a: bver, b: "7.4_8" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "8.1" ) >= 0 && revcomp( a: bver, b: "8.1_10" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "8.2" ) >= 0 && revcomp( a: bver, b: "8.2_8" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "8.3" ) >= 0 && revcomp( a: bver, b: "8.3_2" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "9.0" ) >= 0 && revcomp( a: bver, b: "9.0_2" ) < 0){
	txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\\n";
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

