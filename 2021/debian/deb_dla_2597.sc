if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892597" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2020-13959" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-24 01:23:00 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-18 04:00:09 +0000 (Thu, 18 Mar 2021)" );
	script_name( "Debian LTS: Security Advisory for velocity-tools (DLA-2597-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/03/msg00021.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2597-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2597-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/985221" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'velocity-tools'
  package(s) announced via the DLA-2597-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a cross-site scripting (XSS)
vulnerability in velocity-tools, a collection of useful tools for the
'Velocity' template engine.

The default error page could be exploited to steal session cookies,
perform requests in the name of the victim, used for phishing attacks
and many other similar attacks." );
	script_tag( name: "affected", value: "'velocity-tools' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
2.0-6+deb9u1.

We recommend that you upgrade your velocity-tools packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvelocity-tools-java", ver: "2.0-6+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvelocity-tools-java-doc", ver: "2.0-6+deb9u1", rls: "DEB9" ) )){
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

