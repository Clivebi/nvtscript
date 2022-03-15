if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891794" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-3795" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-08 18:22:00 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-05-21 02:00:10 +0000 (Tue, 21 May 2019)" );
	script_name( "Debian LTS: Security Advisory for libspring-security-2.0-java (DLA-1794-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/05/msg00026.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1794-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libspring-security-2.0-java'
  package(s) announced via the DLA-1794-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability was discovered in libspring-security-2.0-java, a modular
Java/J2EE application security framework, when using
SecureRandomFactoryBean#setSeed to configure a SecureRandom instance,
resulting in insecure randomness." );
	script_tag( name: "affected", value: "'libspring-security-2.0-java' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.0.7.RELEASE-3+deb8u1.

We recommend that you upgrade your libspring-security-2.0-java packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libspring-security-2.0-java-doc", ver: "2.0.7.RELEASE-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libspring-security-acl-2.0-java", ver: "2.0.7.RELEASE-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libspring-security-core-2.0-java", ver: "2.0.7.RELEASE-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libspring-security-ntlm-2.0-java", ver: "2.0.7.RELEASE-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libspring-security-portlet-2.0-java", ver: "2.0.7.RELEASE-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libspring-security-taglibs-2.0-java", ver: "2.0.7.RELEASE-3+deb8u1", rls: "DEB8" ) )){
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

