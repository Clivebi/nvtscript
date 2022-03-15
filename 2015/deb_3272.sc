if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703272" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-4047" );
	script_name( "Debian Security Advisory DSA 3272-1 (ipsec-tools - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-05-23 00:00:00 +0200 (Sat, 23 May 2015)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3272.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ipsec-tools on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 1:0.8.0-14+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 1:0.8.2+20140711-2+deb8u1.

For the testing distribution (stretch) and the unstable distribution
(sid), this problem will be fixed soon.

We recommend that you upgrade your ipsec-tools packages." );
	script_tag( name: "summary", value: "Javantea discovered a NULL
pointer dereference flaw in racoon, the Internet Key Exchange daemon of ipsec-tools.
A remote attacker can use this flaw to cause the IKE daemon to crash via specially
crafted UDP packets, resulting in a denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ipsec-tools", ver: "1:0.8.0-14+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "racoon", ver: "1:0.8.0-14+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

