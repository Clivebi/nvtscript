if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703029" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-3616" );
	script_name( "Debian Security Advisory DSA 3029-1 (nginx - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-09-20 00:00:00 +0200 (Sat, 20 Sep 2014)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3029.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "nginx on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 1.2.1-2.2+wheezy3.

For the testing distribution (jessie), this problem has been fixed in
version 1.6.2-1.

For the unstable distribution (sid), this problem has been fixed in
version 1.6.2-1.

We recommend that you upgrade your nginx packages." );
	script_tag( name: "summary", value: "Antoine Delignat-Lavaud and Karthikeyan Bhargavan discovered that it was
possible to reuse cached SSL sessions in unrelated contexts, allowing
virtual host confusion attacks in some configurations by an attacker in
a privileged network position." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "nginx", ver: "1.2.1-2.2+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-common", ver: "1.2.1-2.2+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-doc", ver: "1.2.1-2.2+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-extras", ver: "1.2.1-2.2+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-extras-dbg", ver: "1.2.1-2.2+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-full", ver: "1.2.1-2.2+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-full-dbg", ver: "1.2.1-2.2+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-light", ver: "1.2.1-2.2+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-light-dbg", ver: "1.2.1-2.2+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-naxsi", ver: "1.2.1-2.2+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-naxsi-dbg", ver: "1.2.1-2.2+wheezy3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-naxsi-ui", ver: "1.2.1-2.2+wheezy3", rls: "DEB7" ) ) != NULL){
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

