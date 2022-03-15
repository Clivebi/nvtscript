if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703341" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-6496" );
	script_name( "Debian Security Advisory DSA 3341-1 (conntrack - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-20 00:00:00 +0200 (Thu, 20 Aug 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3341.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "conntrack on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 1:1.2.1-1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in
version 1:1.4.2-2+deb8u1.

For the unstable distribution (sid), this problem has been fixed in
version 1:1.4.2-3.

We recommend that you upgrade your conntrack packages." );
	script_tag( name: "summary", value: "It was discovered that in certain
configurations, if the relevant conntrack kernel module is not loaded, conntrackd
will crash when handling DCCP, SCTP or ICMPv6 packets." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "conntrack", ver: "1:1.2.1-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "conntrackd", ver: "1:1.2.1-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

