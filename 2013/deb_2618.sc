if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702618" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-0238" );
	script_name( "Debian Security Advisory DSA 2618-1 (ircd-hybrid - denial of service)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-02-07 00:00:00 +0100 (Thu, 07 Feb 2013)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2618.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "ircd-hybrid on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 1:7.2.2.dfsg.2-6.2+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 1:7.2.2.dfsg.2-10.

For the unstable distribution (sid), this problem has been fixed in
version 1:7.2.2.dfsg.2-10.

We recommend that you upgrade your ircd-hybrid packages." );
	script_tag( name: "summary", value: "Bob Nomnomnom reported a Denial of Service vulnerability in IRCD-Hybrid,
an Internet Relay Chat server. A remote attacker may use an error in
the masks validation and crash the server." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "hybrid-dev", ver: "1:7.2.2.dfsg.2-6.2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ircd-hybrid", ver: "1:7.2.2.dfsg.2-6.2+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "hybrid-dev", ver: "1:7.2.2.dfsg.2-10", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ircd-hybrid", ver: "1:7.2.2.dfsg.2-10", rls: "DEB7" ) ) != NULL){
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

