if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892499" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-29668" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-13 04:15:00 +0000 (Wed, 13 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-12-18 04:00:24 +0000 (Fri, 18 Dec 2020)" );
	script_name( "Debian LTS: Security Advisory for sympa (DLA-2499-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/12/msg00026.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2499-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/976020" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sympa'
  package(s) announced via the DLA-2499-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Sympa, a modern mailing list manager, grants full SOAP API access by
sending invalid string as the cookie value, if the SOAP endpoint was
enabled. An attacker could manipulate the mailing lists, including
subscribing e-mails or getting the list of subscribers." );
	script_tag( name: "affected", value: "'sympa' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
6.2.16~dfsg-3+deb9u5.

We recommend that you upgrade your sympa packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sympa", ver: "6.2.16~dfsg-3+deb9u5", rls: "DEB9" ) )){
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
