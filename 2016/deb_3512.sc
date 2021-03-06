if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703512" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-2851" );
	script_name( "Debian Security Advisory DSA 3512-1 (libotr - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-09 00:00:00 +0100 (Wed, 09 Mar 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3512.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|8)" );
	script_tag( name: "affected", value: "libotr on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 3.2.1-1+deb7u2.

For the stable distribution (jessie), this problem has been fixed in
version 4.1.0-2+deb8u1.

We recommend that you upgrade your libotr packages." );
	script_tag( name: "summary", value: "Markus Vervier of X41 D-Sec GmbH discovered
an integer overflow vulnerability in libotr, an off-the-record (OTR) messaging
library, in the way how the sizes of portions of incoming messages were stored. A
remote attacker can exploit this flaw by sending crafted messages to an
application that is using libotr to perform denial of service attacks
(application crash), or potentially, execute arbitrary code with the
privileges of the user running the application." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libotr2", ver: "3.2.1-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libotr2-bin", ver: "3.2.1-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libotr2-dev", ver: "3.2.1-1+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libotr5", ver: "4.1.0-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libotr5-bin", ver: "4.1.0-2+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libotr5-dev", ver: "4.1.0-2+deb8u1", rls: "DEB8" ) ) != NULL){
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

