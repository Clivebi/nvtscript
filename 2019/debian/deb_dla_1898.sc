if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891898" );
	script_version( "2021-09-03T08:01:30+0000" );
	script_cve_id( "CVE-2019-13273", "CVE-2019-13274", "CVE-2019-13451", "CVE-2019-13452", "CVE-2019-13455", "CVE-2019-13484", "CVE-2019-13485", "CVE-2019-13486" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 08:01:30 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-08-27 02:00:34 +0000 (Tue, 27 Aug 2019)" );
	script_name( "Debian LTS: Security Advisory for xymon (DLA-1898-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/08/msg00032.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1898-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xymon'
  package(s) announced via the DLA-1898-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been found in xymon, the network monitoring
application. Remote attackers might leverage these vulnerabilities in the CGI
parsing code (including buffer overflows and XSS) to cause denial of service,
or any other unspecified impact." );
	script_tag( name: "affected", value: "'xymon' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
4.3.17-6+deb8u2.

We recommend that you upgrade your xymon packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "xymon", ver: "4.3.17-6+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xymon-client", ver: "4.3.17-6+deb8u2", rls: "DEB8" ) )){
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

