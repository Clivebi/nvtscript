if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69334" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-1400" );
	script_name( "Debian Security Advisory DSA 2198-1 (tex-common)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202198-1" );
	script_tag( name: "insight", value: "Mathias Svensson discovered that tex-common, a package shipping a number
of scripts and configuration files necessary for TeX, contains insecure
settings for the shell_escape_commands directive.  Depending on the
scenario, this may result in arbitrary code execution when a victim is
tricked into processing a malicious tex-file or this is done in an
automated fashion.


The oldstable distribution (lenny) is not affected by this problem due
to shell_escape being disabled.

For the stable distribution (squeeze), this problem has been fixed in
version 2.08.1.

For the testing (wheezy) and unstable (sid) distributions, this problem
will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your tex-common packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to tex-common
announced via advisory DSA 2198-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "tex-common", ver: "2.08.1", rls: "DEB6" ) ) != NULL){
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

