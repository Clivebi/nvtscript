if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892244" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-13625" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-17 20:15:00 +0000 (Thu, 17 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-06-12 03:00:07 +0000 (Fri, 12 Jun 2020)" );
	script_name( "Debian LTS: Security Advisory for libphp-phpmailer (DLA-2244-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00014.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2244-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libphp-phpmailer'
  package(s) announced via the DLA-2244-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was an escaping issue in
libphp-phpmailer, an email generation utility class for the PHP
programming language.

The `Content-Type` and `Content-Disposition` headers could have
permitted file attachments that bypassed attachment filters which
match on filename extensions. For more information, please see the
following URL:" );
	script_tag( name: "affected", value: "'libphp-phpmailer' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in libphp-phpmailer version
5.2.9+dfsg-2+deb8u6.

We recommend that you upgrade your libphp-phpmailer packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libphp-phpmailer", ver: "5.2.9+dfsg-2+deb8u6", rls: "DEB8" ) )){
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

