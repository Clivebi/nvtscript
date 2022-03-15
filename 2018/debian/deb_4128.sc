if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704128" );
	script_version( "2021-06-21T03:34:17+0000" );
	script_cve_id( "CVE-2017-5660", "CVE-2017-7671" );
	script_name( "Debian Security Advisory DSA 4128-1 (trafficserver - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 03:34:17 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-02 00:00:00 +0100 (Fri, 02 Mar 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-21 16:16:00 +0000 (Wed, 21 Mar 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4128.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "trafficserver on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), these problems have been fixed in
version 7.0.0-6+deb9u1.

We recommend that you upgrade your trafficserver packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/trafficserver" );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in Apache Traffic Server, a
reverse and forward proxy server. They could lead to the use of an
incorrect upstream proxy, or allow a remote attacker to cause a
denial-of-service by application crash." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "trafficserver", ver: "7.0.0-6+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "trafficserver-dev", ver: "7.0.0-6+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "trafficserver-experimental-plugins", ver: "7.0.0-6+deb9u1", rls: "DEB9" ) )){
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

