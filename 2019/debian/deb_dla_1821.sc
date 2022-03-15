if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891821" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2016-6606", "CVE-2016-6607", "CVE-2016-6611", "CVE-2016-6612", "CVE-2016-6613", "CVE-2016-6624", "CVE-2016-6626", "CVE-2016-6627", "CVE-2016-6628", "CVE-2016-6630", "CVE-2016-6631", "CVE-2016-6632", "CVE-2016-9849", "CVE-2016-9850", "CVE-2016-9861", "CVE-2016-9864", "CVE-2019-12616" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)" );
	script_tag( name: "creation_date", value: "2019-06-18 02:00:39 +0000 (Tue, 18 Jun 2019)" );
	script_name( "Debian LTS: Security Advisory for phpmyadmin (DLA-1821-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/06/msg00009.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1821-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/930017" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'phpmyadmin'
  package(s) announced via the DLA-1821-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security vulnerabilities were fixed in phpmyadmin, a MySQL web
administration tool, which prevent possible SQL injection attacks, CSRF,
the bypass of user restrictions, information disclosure or
denial-of-service." );
	script_tag( name: "affected", value: "'phpmyadmin' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
4:4.2.12-2+deb8u6.

We recommend that you upgrade your phpmyadmin packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "phpmyadmin", ver: "4:4.2.12-2+deb8u6", rls: "DEB8" ) )){
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

