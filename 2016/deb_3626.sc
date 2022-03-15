if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703626" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2016-6210" );
	script_name( "Debian Security Advisory DSA 3626-1 (openssh - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-08-02 10:55:52 +0530 (Tue, 02 Aug 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3626.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "openssh on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 1:6.7p1-5+deb8u3.

For the unstable distribution (sid), this problem has been fixed in
version 1:7.2p2-6.

We recommend that you upgrade your openssh packages." );
	script_tag( name: "summary", value: "Eddie Harari reported that the OpenSSH
SSH daemon allows user enumeration through timing differences when trying to
authenticate users. When sshd tries to authenticate a non-existing user, it will
pick up a fixed fake password structure with a hash based on the Blowfish
algorithm. If real users passwords are hashed using SHA256/SHA512, then
a remote attacker can take advantage of this flaw by sending large
passwords, receiving shorter response times from the server for
non-existing users." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "openssh-client", ver: "1:6.7p1-5+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssh-server", ver: "1:6.7p1-5+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "openssh-sftp-server", ver: "1:6.7p1-5+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ssh", ver: "1:6.7p1-5+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ssh-askpass-gnome", ver: "1:6.7p1-5+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "ssh-krb5", ver: "1:6.7p1-5+deb8u3", rls: "DEB8" ) ) != NULL){
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

