if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704684" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-1763" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-05 13:41:00 +0000 (Wed, 05 May 2021)" );
	script_tag( name: "creation_date", value: "2020-05-14 03:00:06 +0000 (Thu, 14 May 2020)" );
	script_name( "Debian: Security Advisory for libreswan (DSA-4684-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4684.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4684-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libreswan'
  package(s) announced via the DSA-4684-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Stephan Zeisberg discovered that the libreswan IPsec implementation
could be forced into a crash/restart via a malformed IKEv1 Informational
Exchange packet, resulting in denial of service." );
	script_tag( name: "affected", value: "'libreswan' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 3.27-6+deb10u1.

We recommend that you upgrade your libreswan packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libreswan", ver: "3.27-6+deb10u1", rls: "DEB10" ) )){
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

