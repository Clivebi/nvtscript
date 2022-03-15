if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704968" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_cve_id( "CVE-2021-40346" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-16 21:15:00 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-09 01:00:07 +0000 (Thu, 09 Sep 2021)" );
	script_name( "Debian: Security Advisory for haproxy (DSA-4968-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB11" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4968.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4968-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4968-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'haproxy'
  package(s) announced via the DSA-4968-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Ori Hollander reported that missing header name length checks in the
htx_add_header() and htx_add_trailer() functions in HAProxy, a fast and
reliable load balancing reverse proxy, could result in request smuggling
attacks or response splitting attacks.

Additionally this update addresses #993303 introduced in DSA 4960-1
causing HAProxy to fail serving URLs with HTTP/2 containing '//'." );
	script_tag( name: "affected", value: "'haproxy' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (bullseye), this problem has been fixed in
version 2.2.9-2+deb11u2.

We recommend that you upgrade your haproxy packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "haproxy", ver: "2.2.9-2+deb11u2", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "haproxy-doc", ver: "2.2.9-2+deb11u2", rls: "DEB11" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-haproxy", ver: "2.2.9-2+deb11u2", rls: "DEB11" ) )){
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
exit( 0 );

