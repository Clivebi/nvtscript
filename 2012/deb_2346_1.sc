if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70559" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-4130", "CVE-2011-0411" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:29:49 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2346-1 (proftpd-dfsg)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202346-1" );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in ProFTPD, an FTP server:

ProFTPD incorrectly uses data from an unencrypted input buffer
after encryption has been enabled with STARTTLS, an issue
similar to CVE-2011-0411.

CVE-2011-4130
ProFTPD uses a response pool after freeing it under
exceptional conditions, possibly leading to remote code
execution.  (The version in lenny is not affected by this
problem.)

For the oldstable distribution (lenny), this problem has been fixed in
version 1.3.1-17lenny8.

For the stable distribution (squeeze), this problem has been fixed in
version 1.3.3a-6squeeze4.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 1.3.4~rc3-2." );
	script_tag( name: "solution", value: "We recommend that you upgrade your proftpd-dfsg packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to proftpd-dfsg
announced via advisory DSA 2346-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "proftpd", ver: "1.3.1-17lenny8", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-basic", ver: "1.3.1-17lenny8", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-doc", ver: "1.3.1-17lenny8", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-ldap", ver: "1.3.1-17lenny8", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-mysql", ver: "1.3.1-17lenny8", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-pgsql", ver: "1.3.1-17lenny8", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-basic", ver: "1.3.3a-6squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-dev", ver: "1.3.3a-6squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-doc", ver: "1.3.3a-6squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-ldap", ver: "1.3.3a-6squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-mysql", ver: "1.3.3a-6squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-odbc", ver: "1.3.3a-6squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-pgsql", ver: "1.3.3a-6squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-sqlite", ver: "1.3.3a-6squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-basic", ver: "1.3.4a-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-dev", ver: "1.3.4a-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-doc", ver: "1.3.4a-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-ldap", ver: "1.3.4a-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-mysql", ver: "1.3.4a-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-odbc", ver: "1.3.4a-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-pgsql", ver: "1.3.4a-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-sqlite", ver: "1.3.4a-1", rls: "DEB7" ) ) != NULL){
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

