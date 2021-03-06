if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704514" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-15892" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-09-05 02:00:04 +0000 (Thu, 05 Sep 2019)" );
	script_name( "Debian Security Advisory DSA 4514-1 (varnish - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4514.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4514-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'varnish'
  package(s) announced via the DSA-4514-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Alf-Andre Walla discovered a remotely triggerable assert in the Varnish
web accelerator, sending a malformed HTTP request could result in denial
of service.

The oldstable distribution (stretch) is not affected." );
	script_tag( name: "affected", value: "'varnish' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 6.1.1-1+deb10u1.

We recommend that you upgrade your varnish packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvarnishapi-dev", ver: "6.1.1-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvarnishapi2", ver: "6.1.1-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "varnish", ver: "6.1.1-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "varnish-doc", ver: "6.1.1-1+deb10u1", rls: "DEB10" ) )){
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

