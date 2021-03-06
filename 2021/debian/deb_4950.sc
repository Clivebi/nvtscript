if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704950" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2019-10156", "CVE-2019-10206", "CVE-2019-14846", "CVE-2019-14864", "CVE-2019-14904", "CVE-2020-10684", "CVE-2020-10685", "CVE-2020-10729", "CVE-2020-14330", "CVE-2020-14332", "CVE-2020-14365", "CVE-2020-1733", "CVE-2020-1735", "CVE-2020-1739", "CVE-2020-1740", "CVE-2020-1746", "CVE-2020-1753", "CVE-2021-20228" );
	script_tag( name: "cvss_base", value: "6.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-29 18:39:00 +0000 (Tue, 29 Sep 2020)" );
	script_tag( name: "creation_date", value: "2021-08-08 03:00:26 +0000 (Sun, 08 Aug 2021)" );
	script_name( "Debian: Security Advisory for ansible (DSA-4950-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4950.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4950-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4950-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ansible'
  package(s) announced via the DSA-4950-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been found in Ansible, a configuration
management, deployment and task execution system, which could result in
information disclosure or argument injection. In addition a race
condition in become_user was fixed." );
	script_tag( name: "affected", value: "'ansible' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 2.7.7+dfsg-1+deb10u1.

We recommend that you upgrade your ansible packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ansible", ver: "2.7.7+dfsg-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ansible-doc", ver: "2.7.7+dfsg-1+deb10u1", rls: "DEB10" ) )){
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

