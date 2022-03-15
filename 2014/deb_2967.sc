if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702967" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-4617" );
	script_name( "Debian Security Advisory DSA 2967-1 (gnupg - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-06-25 00:00:00 +0200 (Wed, 25 Jun 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2967.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "gnupg on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 1.4.12-7+deb7u4.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.16-1.2.

We recommend that you upgrade your gnupg packages." );
	script_tag( name: "summary", value: "Jean-Ren� Reinhard, Olivier Levillain and Florian Maury reported that
GnuPG, the GNU Privacy Guard, did not properly parse certain garbled
compressed data packets. A remote attacker could use this flaw to mount
a denial of service against GnuPG by triggering an infinite loop." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gnupg", ver: "1.4.12-7+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gnupg-curl", ver: "1.4.12-7+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gpgv", ver: "1.4.12-7+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gpgv-win32", ver: "1.4.12-7+deb7u4", rls: "DEB7" ) ) != NULL){
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

