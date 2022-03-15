if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72625" );
	script_cve_id( "CVE-2012-2251", "CVE-2012-2252" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-12-04 11:42:07 -0500 (Tue, 04 Dec 2012)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Debian Security Advisory DSA 2578-1 (rssh)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202578-1" );
	script_tag( name: "insight", value: "James Clawson discovered that rssh, a restricted shell for OpenSSH to be used
with scp/sftp, rdist and cvs, was not correctly filtering command line options.
This could be used to force the execution of a remote script and thus allow
arbitrary command execution. Two CVE were assigned:

CVE-2012-2251
Incorrect filtering of command line when using rsync protocol. It was
for example possible to pass dangerous options after a -- switch. The rsync
protocol support has been added in a Debian (and Fedora/Red Hat) specific
patch, so this vulnerability doesn't affect upstream.

CVE-2012-2251
Incorrect filtering of the --rsh option: the filter preventing usage of the

  - -rsh= option would not prevent passing --rsh. This vulnerability affects
upstream code.

For the stable distribution (squeeze), this problem has been fixed in
version 2.3.2-13squeeze2.

For the testing distribution (wheezy), this problem has been fixed in
version 2.3.3-6.

For the unstable distribution (sid), this problem has been fixed in
version 2.3.3-6." );
	script_tag( name: "solution", value: "We recommend that you upgrade your rssh packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to rssh
announced via advisory DSA 2578-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "rssh", ver: "2.3.2-13squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "rssh", ver: "2.3.3-6", rls: "DEB7" ) ) != NULL){
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

