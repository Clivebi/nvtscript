if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892433" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-26939" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-28 15:14:00 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2020-11-06 04:00:09 +0000 (Fri, 06 Nov 2020)" );
	script_name( "Debian LTS: Security Advisory for bouncycastle (DLA-2433-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/11/msg00007.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2433-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bouncycastle'
  package(s) announced via the DLA-2433-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was an issue in the bouncycastle crypto
library where attackers could obtain sensitive information due to
observable differences in its response to invalid input." );
	script_tag( name: "affected", value: "'bouncycastle' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
1.56-1+deb9u3.

We recommend that you upgrade your bouncycastle packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libbcmail-java", ver: "1.56-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbcmail-java-doc", ver: "1.56-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbcpg-java", ver: "1.56-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbcpg-java-doc", ver: "1.56-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbcpkix-java", ver: "1.56-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbcpkix-java-doc", ver: "1.56-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbcprov-java", ver: "1.56-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libbcprov-java-doc", ver: "1.56-1+deb9u3", rls: "DEB9" ) )){
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

