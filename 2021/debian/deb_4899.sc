if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704899" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2021-2161" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-10 13:51:00 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-04-25 03:00:27 +0000 (Sun, 25 Apr 2021)" );
	script_name( "Debian: Security Advisory for openjdk-11 (DSA-4899-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4899.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4899-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4899-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openjdk-11'
  package(s) announced via the DSA-4899-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the OpenJDK Java platform incompletely enforced
configuration settings used in Jar signing verifications." );
	script_tag( name: "affected", value: "'openjdk-11' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 11.0.11+9-1~deb10u1.

We recommend that you upgrade your openjdk-11 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-dbg", ver: "11.0.11+9-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-demo", ver: "11.0.11+9-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-doc", ver: "11.0.11+9-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jdk", ver: "11.0.11+9-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jdk-headless", ver: "11.0.11+9-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre", ver: "11.0.11+9-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-headless", ver: "11.0.11+9-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-jre-zero", ver: "11.0.11+9-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openjdk-11-source", ver: "11.0.11+9-1~deb10u1", rls: "DEB10" ) )){
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

