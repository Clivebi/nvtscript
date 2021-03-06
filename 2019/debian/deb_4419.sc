if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704419" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2019-9942" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-01 08:29:00 +0000 (Mon, 01 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-03-28 22:00:00 +0000 (Thu, 28 Mar 2019)" );
	script_name( "Debian Security Advisory DSA 4419-1 (twig - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4419.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4419-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'twig'
  package(s) announced via the DSA-4419-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Fabien Potencier discovered that twig, a template engine for PHP, did
not correctly enforce sandboxing. This could result in potential
information disclosure." );
	script_tag( name: "affected", value: "'twig' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1.24.0-2+deb9u1.

We recommend that you upgrade your twig packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "php-twig", ver: "1.24.0-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php-twig-doc", ver: "1.24.0-2+deb9u1", rls: "DEB9" ) )){
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

