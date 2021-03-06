if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703134" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-1306" );
	script_name( "Debian Security Advisory DSA 3134-1 (sympa - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-01-20 00:00:00 +0100 (Tue, 20 Jan 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3134.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "sympa on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 6.1.11~dfsg-5+deb7u2.

For the upcoming stable distribution (jessie), this problem will be
fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 6.1.23~dfsg-2.

We recommend that you upgrade your sympa packages." );
	script_tag( name: "summary", value: "A vulnerability has been discovered
in the web interface of sympa, a mailing list manager. An attacker could take
advantage of this flaw in the newsletter posting area, which allows sending to
a list, or to oneself, any file located on the server filesystem and readable by
the sympa user." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "sympa", ver: "6.1.11~dfsg-5+deb7u2", rls: "DEB7" ) ) != NULL){
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

