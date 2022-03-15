if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704799" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2020-29074" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-25 00:01:00 +0000 (Thu, 25 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-11-29 04:00:06 +0000 (Sun, 29 Nov 2020)" );
	script_name( "Debian: Security Advisory for x11vnc (DSA-4799-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4799.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4799-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'x11vnc'
  package(s) announced via the DSA-4799-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Guenal Davalan reported a flaw in x11vnc, a VNC server to allow remote
access to an existing X session. x11vnc creates shared memory segments
with 0777 mode. A local attacker can take advantage of this flaw for
information disclosure, denial of service or interfering with the VNC
session of another user on the host." );
	script_tag( name: "affected", value: "'x11vnc' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 0.9.13-6+deb10u1.

We recommend that you upgrade your x11vnc packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "x11vnc", ver: "0.9.13-6+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "x11vnc-data", ver: "0.9.13-6+deb10u1", rls: "DEB10" ) )){
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

