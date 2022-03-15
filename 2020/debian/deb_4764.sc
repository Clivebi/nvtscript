if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704764" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2019-20917", "CVE-2020-25269" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-20 07:15:00 +0000 (Sun, 20 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-20 03:00:07 +0000 (Sun, 20 Sep 2020)" );
	script_name( "Debian: Security Advisory for inspircd (DSA-4764-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4764.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4764-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'inspircd'
  package(s) announced via the DSA-4764-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two security issues were discovered in the pgsql and mysql modules of
the InspIRCd IRC daemon, which could result in denial of service." );
	script_tag( name: "affected", value: "'inspircd' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 2.0.27-1+deb10u1.

We recommend that you upgrade your inspircd packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "inspircd", ver: "2.0.27-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inspircd-dbg", ver: "2.0.27-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "inspircd-dev", ver: "2.0.27-1+deb10u1", rls: "DEB10" ) )){
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

