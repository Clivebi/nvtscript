if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704151" );
	script_version( "2021-06-16T02:47:07+0000" );
	script_cve_id( "CVE-2018-1000140" );
	script_name( "Debian Security Advisory DSA 4151-1 (librelp - security update)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:47:07 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-26 00:00:00 +0200 (Mon, 26 Mar 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4151.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "librelp on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1.2.7-2+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 1.2.12-1+deb9u1.

We recommend that you upgrade your librelp packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/librelp" );
	script_tag( name: "summary", value: "Bas van Schaik and Kevin Backhouse discovered a stack-based buffer
overflow vulnerability in librelp, a library providing reliable event
logging over the network, triggered while checking x509 certificates
from a peer. A remote attacker able to connect to rsyslog can take
advantage of this flaw for remote code execution by sending a specially
crafted x509 certificate." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "librelp-dev", ver: "1.2.7-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librelp0", ver: "1.2.7-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librelp-dev", ver: "1.2.12-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "librelp0", ver: "1.2.12-1+deb9u1", rls: "DEB9" ) )){
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

