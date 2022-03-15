if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703445" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-8557" );
	script_name( "Debian Security Advisory DSA 3445-1 (pygments - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-01-13 00:00:00 +0100 (Wed, 13 Jan 2016)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3445.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8|7)" );
	script_tag( name: "affected", value: "pygments on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 1.5+dfsg-1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 2.0.1+dfsg-1.1+deb8u1.

For the testing distribution (stretch), this problem has been fixed
in version 2.0.1+dfsg-2.

For the unstable distribution (sid), this problem has been fixed in
version 2.0.1+dfsg-2.

We recommend that you upgrade your pygments packages." );
	script_tag( name: "summary", value: "Javantea discovered that pygments,
a generic syntax highlighter, is prone to a shell injection vulnerability allowing
a remote attacker to execute arbitrary code via shell metacharacters in a font
name." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "python-pygments", ver: "2.0.1+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pygments-doc", ver: "2.0.1+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pygments", ver: "2.0.1+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pygments", ver: "2.0.1+dfsg-1.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pygments-doc", ver: "2.0.1+dfsg-1.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pygments", ver: "2.0.1+dfsg-1.1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-pygments", ver: "1.5+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python3-pygments", ver: "1.5+dfsg-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

