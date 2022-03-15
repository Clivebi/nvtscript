if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703793" );
	script_version( "2021-09-13T13:01:42+0000" );
	script_cve_id( "CVE-2016-6252", "CVE-2017-2616" );
	script_name( "Debian Security Advisory DSA 3793-1 (shadow - security update)" );
	script_tag( name: "last_modification", value: "2021-09-13 13:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-24 00:00:00 +0100 (Fri, 24 Feb 2017)" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:26:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3793.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "shadow on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 1:4.2-3+deb8u3.

We recommend that you upgrade your shadow packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in the shadow suite. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-6252
An integer overflow vulnerability was discovered, potentially
allowing a local user to escalate privileges via crafted input to
the newuidmap utility.

CVE-2017-2616
Tobias Stoeckmann discovered that su does not properly handle
clearing a child PID. A local attacker can take advantage of this
flaw to send SIGKILL to other processes with root privileges,
resulting in denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "login", ver: "1:4.2-3+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "passwd", ver: "1:4.2-3+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "uidmap", ver: "1:4.2-3+deb8u3", rls: "DEB8" ) ) != NULL){
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

