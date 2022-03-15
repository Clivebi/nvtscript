if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702874" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-0467" );
	script_name( "Debian Security Advisory DSA 2874-1 (mutt - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-12 00:00:00 +0100 (Wed, 12 Mar 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2874.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "mutt on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.5.20-9+squeeze3.

For the stable distribution (wheezy), this problem has been fixed in
version 1.5.21-6.2+deb7u2.

For the unstable distribution (sid), this problem has been fixed in
version 1.5.22-2.

We recommend that you upgrade your mutt packages." );
	script_tag( name: "summary", value: "Beatrice Torracca and Evgeni Golov discovered a buffer overflow in the
mutt mailreader. Malformed RFC2047 header lines could result in denial
of service or potentially the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "mutt", ver: "1.5.20-9+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mutt-dbg", ver: "1.5.20-9+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mutt-patched", ver: "1.5.20-9+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mutt", ver: "1.5.21-6.2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mutt-dbg", ver: "1.5.21-6.2+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "mutt-patched", ver: "1.5.21-6.2+deb7u2", rls: "DEB7" ) ) != NULL){
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

