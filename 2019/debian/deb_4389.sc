if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704389" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2018-20340" );
	script_name( "Debian Security Advisory DSA 4389-1 (libu2f-host - security update)" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-11 00:00:00 +0100 (Mon, 11 Feb 2019)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-05 17:15:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4389.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "libu2f-host on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1.1.2-2+deb9u1.

We recommend that you upgrade your libu2f-host packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/libu2f-host" );
	script_tag( name: "summary", value: "Christian Reitter discovered that libu2f-host, a library implementing
the host-side of the U2F protocol, failed to properly check for a
buffer overflow. This would allow an attacker with a custom made
malicious USB device masquerading as a security key, and physical
access to a computer where PAM U2F or an application with libu2f-host
integrated, to potentially execute arbitrary code on that computer." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libu2f-host-dev", ver: "1.1.2-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libu2f-host0", ver: "1.1.2-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "u2f-host", ver: "1.1.2-2+deb9u1", rls: "DEB9" ) )){
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

