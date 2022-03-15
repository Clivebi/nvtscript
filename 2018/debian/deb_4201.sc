if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704201" );
	script_version( "2021-06-17T04:16:32+0000" );
	script_cve_id( "CVE-2018-10471", "CVE-2018-10472", "CVE-2018-10981", "CVE-2018-10982", "CVE-2018-8897" );
	script_name( "Debian Security Advisory DSA 4201-1 (xen - security update)" );
	script_tag( name: "last_modification", value: "2021-06-17 04:16:32 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-15 00:00:00 +0200 (Tue, 15 May 2018)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4201.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "xen on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6.

We recommend that you upgrade your xen packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/xen" );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in the Xen hypervisor:

CVE-2018-8897
Andy Lutomirski and Nick Peterson discovered that incorrect handling
of debug exceptions could result in privilege escalation.

CVE-2018-10471
An error was discovered in the mitigations against Meltdown which
could result in denial of service.

CVE-2018-10472
Anthony Perard discovered that incorrect parsing of CDROM images
can result in information disclosure.

CVE-2018-10981
Jan Beulich discovered that malformed device models could result
in denial of service.

CVE-2018-10982
Roger Pau Monne discovered that incorrect handling of high precision
event timers could result in denial of service and potentially
privilege escalation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxen-4.8", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxen-dev", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxenstore3.0", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-hypervisor-4.8-amd64", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-system-amd64", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-4.8", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xen-utils-common", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xenstore-utils", ver: "4.8.3+xsa262+shim4.10.0+comet3-1+deb9u6", rls: "DEB9" ) )){
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

