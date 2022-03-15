if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704118" );
	script_version( "2021-06-17T04:16:32+0000" );
	script_cve_id( "CVE-2017-15698" );
	script_name( "Debian Security Advisory DSA 4118-1 (tomcat-native - security update)" );
	script_tag( name: "last_modification", value: "2021-06-17 04:16:32 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-17 00:00:00 +0100 (Sat, 17 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-25 11:35:00 +0000 (Mon, 25 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4118.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "tomcat-native on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1.1.32~repack-2+deb8u1.

For the stable distribution (stretch), this problem has been fixed in
version 1.2.12-2+deb9u1.

We recommend that you upgrade your tomcat-native packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/tomcat-native" );
	script_tag( name: "summary", value: "Jonas Klempel reported that tomcat-native, a library giving Tomcat
access to the Apache Portable Runtime (APR) library's network connection
(socket) implementation and random-number generator, does not properly
handle fields longer than 127 bytes when parsing the AIA-Extension field
of a client certificate. If OCSP checks are used, this could result in
client certificates that should have been rejected to be accepted." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libtcnative-1", ver: "1.1.32~repack-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtcnative-1", ver: "1.2.12-2+deb9u1", rls: "DEB9" ) )){
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

