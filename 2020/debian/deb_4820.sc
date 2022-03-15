if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704820" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-29565" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-09 15:08:00 +0000 (Tue, 09 Mar 2021)" );
	script_tag( name: "creation_date", value: "2020-12-29 04:00:07 +0000 (Tue, 29 Dec 2020)" );
	script_name( "Debian: Security Advisory for horizon (DSA-4820-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4820.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4820-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'horizon'
  package(s) announced via the DSA-4820-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Pritam Singh discovered an open redirect in the workflow forms of
OpenStack Horizon." );
	script_tag( name: "affected", value: "'horizon' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 3:14.0.2-3+deb10u2.

We recommend that you upgrade your horizon packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "horizon-doc", ver: "3:14.0.2-3+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openstack-dashboard", ver: "3:14.0.2-3+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "openstack-dashboard-apache", ver: "3:14.0.2-3+deb10u2", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-django-horizon", ver: "3:14.0.2-3+deb10u2", rls: "DEB10" ) )){
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

