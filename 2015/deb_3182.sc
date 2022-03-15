if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703182" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-1782" );
	script_name( "Debian Security Advisory DSA 3182-1 (libssh2 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-11 00:00:00 +0100 (Wed, 11 Mar 2015)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3182.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libssh2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 1.4.2-1.1+deb7u1.

We recommend that you upgrade your libssh2 packages." );
	script_tag( name: "summary", value: "Mariusz Ziulek reported that libssh2,
a SSH2 client-side library, was reading and using the SSH_MSG_KEXINIT packet
without doing sufficient range checks when negotiating a new SSH session with a
remote server. A malicious attacker could man in the middle a real server and
cause a client using the libssh2 library to crash (denial of service) or
otherwise read and use unintended memory areas in this process." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libssh2-1:amd64", ver: "1.4.2-1.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh2-1:i386", ver: "1.4.2-1.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh2-1-dbg", ver: "1.4.2-1.1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh2-1-dev", ver: "1.4.2-1.1+deb7u1", rls: "DEB7" ) ) != NULL){
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

