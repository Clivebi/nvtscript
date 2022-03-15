if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703278" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2014-8111" );
	script_name( "Debian Security Advisory DSA 3278-1 (libapache-mod-jk - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-03 00:00:00 +0200 (Wed, 03 Jun 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3278.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libapache-mod-jk on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution
(wheezy), this problem has been fixed in version 1:1.2.37-1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 1:1.2.37-4+deb8u1.

For the testing distribution (stretch), this problem has been fixed
in version 1:1.2.40+svn150520-1.

For the unstable distribution (sid), this problem has been fixed in
version 1:1.2.40+svn150520-1.

We recommend that you upgrade your libapache-mod-jk packages." );
	script_tag( name: "summary", value: "An information disclosure flaw due
to incorrect JkMount/JkUnmount directives processing was found in the Apache 2
module mod_jk to forward requests from the Apache web server to Tomcat. A
JkUnmount rule for a subtree of a previous JkMount rule could be ignored. This
could allow a remote attacker to potentially access a private artifact in a tree
that would otherwise not be accessible to them." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libapache-mod-jk-doc", ver: "1:1.2.37-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapache2-mod-jk", ver: "1:1.2.37-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

