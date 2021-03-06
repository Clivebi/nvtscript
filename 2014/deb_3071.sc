if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703071" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-1544" );
	script_name( "Debian Security Advisory DSA 3071-1 (nss - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-11-11 00:00:00 +0100 (Tue, 11 Nov 2014)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3071.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "nss on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 2:3.14.5-1+deb7u3.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 2:3.16.3-1.

For the unstable distribution (sid), this problem has been fixed in
version 2:3.16.3-1.

We recommend that you upgrade your nss packages." );
	script_tag( name: "summary", value: "In nss, a set of libraries designed to support cross-platform
development of security-enabled client and server applications, Tyson
Smith and Jesse Schwartzentruber discovered a use-after-free
vulnerability that allows remote attackers to execute arbitrary code by
triggering the improper removal of an NSSCertificate structure from a
trust domain." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libnss3", ver: "2:3.14.5-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-1d", ver: "2:3.14.5-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dbg", ver: "2:3.14.5-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dev", ver: "2:3.14.5-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-tools", ver: "2:3.14.5-1+deb7u3", rls: "DEB7" ) ) != NULL){
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

