if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702765" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4362" );
	script_name( "Debian Security Advisory DSA 2765-1 (davfs2 - privilege escalation)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-26 00:00:00 +0200 (Thu, 26 Sep 2013)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2765.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "davfs2 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.4.6-1.1+squeeze1.

For the stable distribution (wheezy), this problem has been fixed in
version 1.4.6-1.1+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 1.4.7-3.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.7-3.

We recommend that you upgrade your davfs2 packages." );
	script_tag( name: "summary", value: "Davfs2, a filesystem client for WebDAV, calls the function system()
insecurely while is setuid root. This might allow a privilege escalation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "davfs2", ver: "1.4.6-1.1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "davfs2", ver: "1.4.6-1.1+deb7u1", rls: "DEB7" ) ) != NULL){
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

