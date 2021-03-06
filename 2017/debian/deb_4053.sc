if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704053" );
	script_version( "2021-09-14T09:01:51+0000" );
	script_cve_id( "CVE-2017-16943", "CVE-2017-16944" );
	script_name( "Debian Security Advisory DSA 4053-1 (exim4 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 09:01:51 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-30 00:00:00 +0100 (Thu, 30 Nov 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-04 18:15:00 +0000 (Tue, 04 May 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2017/dsa-4053.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "exim4 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 4.89-2+deb9u2. Default installations disable advertising the
ESMTP CHUNKING extension and are not affected by these issues.

We recommend that you upgrade your exim4 packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/exim4" );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in Exim, a mail transport
agent. The Common Vulnerabilities and Exposures project identifies the
following issues:

CVE-2017-16943
A use-after-free vulnerability was discovered in Exim's routines
responsible for parsing mail headers. A remote attacker can take
advantage of this flaw to cause Exim to crash, resulting in a denial
of service, or potentially for remote code execution.

CVE-2017-16944
It was discovered that Exim does not properly handle BDAT data
headers allowing a remote attacker to cause Exim to crash, resulting
in a denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "exim4", ver: "4.89-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-base", ver: "4.89-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-config", ver: "4.89-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.89-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-heavy-dbg", ver: "4.89-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.89-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-daemon-light-dbg", ver: "4.89-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-dbg", ver: "4.89-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "exim4-dev", ver: "4.89-2+deb9u2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "eximon4", ver: "4.89-2+deb9u2", rls: "DEB9" ) )){
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

