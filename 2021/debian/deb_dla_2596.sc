if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892596" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2020-9484", "CVE-2020-9494", "CVE-2021-24122", "CVE-2021-25122", "CVE-2021-25329" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-11 21:23:00 +0000 (Thu, 11 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-17 04:00:10 +0000 (Wed, 17 Mar 2021)" );
	script_name( "Debian LTS: Security Advisory for tomcat8 (DLA-2596-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/03/msg00018.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2596-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2596-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat8'
  package(s) announced via the DLA-2596-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Three security issues have been detected in tomcat8.

CVE-2021-24122

When serving resources from a network location using the NTFS file system,
Apache Tomcat versions 8.5.0 to 8.5.59 is susceptible to JSP source code
disclosure in some configurations. The root cause was the unexpected
behaviour of the JRE API File.getCanonicalPath() which in turn was caused
by the inconsistent behaviour of the Windows API (FindFirstFileW) in some
circumstances.

CVE-2021-25122

When responding to new h2c connection requests, Apache Tomcat could
duplicate request headers and a limited amount of request body from one
request to another meaning user A and user B could both see the results
of user A's request.

CVE-2021-25329

The fix for 2020-9484 was incomplete. When using Apache Tomcat 8.5.0 to
8.5.61 with a configuration edge case that was highly unlikely to be used,
the Tomcat instance was still vulnerable to CVE-2020-9494. Note that both
the previously published prerequisites for CVE-2020-9484 and the
previously published mitigations for CVE-2020-9484 also apply to this
issue." );
	script_tag( name: "affected", value: "'tomcat8' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
8.5.54-0+deb9u6.

We recommend that you upgrade your tomcat8 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.1-java", ver: "8.5.54-0+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libservlet3.1-java-doc", ver: "8.5.54-0+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtomcat8-embed-java", ver: "8.5.54-0+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtomcat8-java", ver: "8.5.54-0+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8", ver: "8.5.54-0+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-admin", ver: "8.5.54-0+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-common", ver: "8.5.54-0+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-docs", ver: "8.5.54-0+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-examples", ver: "8.5.54-0+deb9u6", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "tomcat8-user", ver: "8.5.54-0+deb9u6", rls: "DEB9" ) )){
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

