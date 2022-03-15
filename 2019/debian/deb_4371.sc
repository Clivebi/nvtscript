if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704371" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-3462" );
	script_name( "Debian Security Advisory DSA 4371-1 (apt - security update)" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-22 00:00:00 +0100 (Tue, 22 Jan 2019)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4371.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "apt on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1.4.9.

We recommend that you upgrade your apt packages.

Please note the specific upgrade instructions within the referenced vendor advisory." );
	script_tag( name: "summary", value: "Max Justicz discovered a vulnerability in APT, the high level package manager.
The code handling HTTP redirects in the HTTP transport method doesn't properly
sanitize fields transmitted over the wire. This vulnerability could be used by
an attacker located as a man-in-the-middle between APT and a mirror to inject
malicious content in the HTTP connection. This content could then be recognized
as a valid package by APT and used later for code execution with root
privileges on the target machine." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "apt", ver: "1.4.9", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apt-doc", ver: "1.4.9", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apt-transport-https", ver: "1.4.9", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "apt-utils", ver: "1.4.9", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-inst2.0", ver: "1.4.9", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-pkg-dev", ver: "1.4.9", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-pkg-doc", ver: "1.4.9", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libapt-pkg5.0", ver: "1.4.9", rls: "DEB9" ) ) != NULL){
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

