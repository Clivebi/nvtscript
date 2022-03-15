if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704873" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2020-25097" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 11:15:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2021-03-25 04:00:11 +0000 (Thu, 25 Mar 2021)" );
	script_name( "Debian: Security Advisory for squid (DSA-4873-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4873.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4873-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4873-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'squid'
  package(s) announced via the DSA-4873-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Jianjun Chen discovered that the Squid proxy caching server was
susceptible to HTTP request smuggling." );
	script_tag( name: "affected", value: "'squid' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 4.6-1+deb10u5.

We recommend that you upgrade your squid packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "squid", ver: "4.6-1+deb10u5", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squid-cgi", ver: "4.6-1+deb10u5", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squid-common", ver: "4.6-1+deb10u5", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squid-purge", ver: "4.6-1+deb10u5", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squid3", ver: "4.6-1+deb10u5", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "squidclient", ver: "4.6-1+deb10u5", rls: "DEB10" ) )){
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

