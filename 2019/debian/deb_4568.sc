if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704568" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-3466" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-03 21:15:00 +0000 (Tue, 03 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-11-17 03:00:04 +0000 (Sun, 17 Nov 2019)" );
	script_name( "Debian Security Advisory DSA 4568-1 (postgresql-common - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|9)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4568.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4568-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql-common'
  package(s) announced via the DSA-4568-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Rich Mirch discovered that the pg_ctlcluster script didn't drop
privileges when creating socket/statistics temporary directories, which
could result in local privilege escalation." );
	script_tag( name: "affected", value: "'postgresql-common' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (stretch), this problem has been fixed
in version 181+deb9u3.

For the stable distribution (buster), this problem has been fixed in
version 200+deb10u3.

We recommend that you upgrade your postgresql-common packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "postgresql-common", ver: "200+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "postgresql-common", ver: "181+deb9u3", rls: "DEB9" ) )){
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

