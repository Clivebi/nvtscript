if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703476" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-0766", "CVE-2016-0773" );
	script_name( "Debian Security Advisory DSA 3476-1 (postgresql-9.4 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-02-13 00:00:00 +0100 (Sat, 13 Feb 2016)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3476.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "postgresql-9.4 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 9.4.6-0+deb8u1.

We recommend that you upgrade your postgresql-9.4 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been
found in PostgreSQL-9.4, a SQL database system.

CVE-2016-0766
A privilege escalation vulnerability for users of PL/Java was
discovered. Certain custom configuration settings (GUCs) for PL/Java
will now be modifiable only by the database superuser to mitigate
this issue.

CVE-2016-0773
Tom Lane and Greg Stark discovered a flaw in the way PostgreSQL
processes specially crafted regular expressions. Very large
character ranges in bracket expressions could cause infinite
loops or memory overwrites. A remote attacker can exploit this
flaw to cause a denial of service or, potentially, to execute
arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libecpg-compat3", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libecpg-dev", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libecpg6", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpgtypes3", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpq-dev", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpq5", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-9.4", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-9.4-dbg", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-client-9.4", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-contrib-9.4", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-doc-9.4", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plperl-9.4", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plpython-9.4", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plpython3-9.4", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-pltcl-9.4", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-server-dev-9.4", ver: "9.4.6-0+deb8u1", rls: "DEB8" ) ) != NULL){
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

