if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704818" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2020-10936", "CVE-2020-26880", "CVE-2020-26932", "CVE-2020-29668", "CVE-2020-9369" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-24 12:15:00 +0000 (Thu, 24 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-25 04:00:11 +0000 (Fri, 25 Dec 2020)" );
	script_name( "Debian: Security Advisory for sympa (DSA-4818-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4818.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4818-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sympa'
  package(s) announced via the DSA-4818-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in Sympa, a mailing list
manager, which could result in local privilege escalation, denial of
service or unauthorized access via the SOAP API.

Additionally to mitigate CVE-2020-26880 the sympa_newaliases-wrapper is no longer installed
setuid root by default. A new Debconf question is introduced to allow
setuid installations in setups where it is needed." );
	script_tag( name: "affected", value: "'sympa' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 6.2.40~dfsg-1+deb10u1.

We recommend that you upgrade your sympa packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sympa", ver: "6.2.40~dfsg-1+deb10u1", rls: "DEB10" ) )){
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

