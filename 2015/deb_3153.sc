if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703153" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2014-5352", "CVE-2014-9421", "CVE-2014-9422", "CVE-2014-9423" );
	script_name( "Debian Security Advisory DSA 3153-1 (krb5 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-02-03 00:00:00 +0100 (Tue, 03 Feb 2015)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3153.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "krb5 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
these problems have been fixed in version 1.10.1+dfsg-5+deb7u3.

For the unstable distribution (sid), these problems have been fixed in
version 1.12.1+dfsg-17.

We recommend that you upgrade your krb5 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have
been found in krb5, the MIT implementation of Kerberos:

CVE-2014-5352
Incorrect memory management in the libgssapi_krb5 library might
result in denial of service or the execution of arbitrary code.

CVE-2014-9421
Incorrect memory management in kadmind's processing of XDR data
might result in denial of service or the execution of arbitrary code.

CVE-2014-9422
Incorrect processing of two-component server principals might result
in impersonation attacks.

CVE-2014-9423
An information leak in the libgssrpc library." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "krb5-admin-server", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "krb5-doc", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "krb5-gss-samples", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "krb5-kdc", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "krb5-kdc-ldap", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "krb5-locales", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "krb5-multidev", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "krb5-pkinit", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "krb5-user", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgssapi-krb5-2", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgssrpc4", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libk5crypto3", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkadm5clnt-mit8", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkadm5srv-mit8", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkdb5-6", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkrb5-3", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkrb5-dbg", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkrb5-dev", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libkrb5support0", ver: "1.10.1+dfsg-5+deb7u3", rls: "DEB7" ) ) != NULL){
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

