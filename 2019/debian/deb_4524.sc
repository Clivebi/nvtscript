if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704524" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-16235", "CVE-2019-16236", "CVE-2019-16237" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-14 14:26:00 +0000 (Mon, 14 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-09-18 02:00:06 +0000 (Wed, 18 Sep 2019)" );
	script_name( "Debian Security Advisory DSA 4524-1 (dino-im - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4524.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4524-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dino-im'
  package(s) announced via the DSA-4524-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple vulnerabilities have been discovered in the Dino XMPP client,
which could allow spoofing message, manipulation of a user's roster
(contact list) and unauthorised sending of message carbons." );
	script_tag( name: "affected", value: "'dino-im' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 0.0.git20181129-1+deb10u1.

We recommend that you upgrade your dino-im packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "dino-im", ver: "0.0.git20181129-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "dino-im-common", ver: "0.0.git20181129-1+deb10u1", rls: "DEB10" ) )){
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

