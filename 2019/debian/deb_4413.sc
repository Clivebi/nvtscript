if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704413" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2019-9755" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-27 03:15:00 +0000 (Mon, 27 Jul 2020)" );
	script_tag( name: "creation_date", value: "2019-03-20 22:00:00 +0000 (Wed, 20 Mar 2019)" );
	script_name( "Debian Security Advisory DSA 4413-1 (ntfs-3g - security update)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2019/dsa-4413.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4413-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntfs-3g'
  package(s) announced via the DSA-4413-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A heap-based buffer overflow was discovered in NTFS-3G, a read-write
NTFS driver for FUSE. A local user can take advantage of this flaw for
local root privilege escalation." );
	script_tag( name: "affected", value: "'ntfs-3g' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1:2016.2.22AR.1+dfsg-1+deb9u1.

We recommend that you upgrade your ntfs-3g packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libntfs-3g871", ver: "1:2016.2.22AR.1+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ntfs-3g", ver: "1:2016.2.22AR.1+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ntfs-3g-dbg", ver: "1:2016.2.22AR.1+dfsg-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ntfs-3g-dev", ver: "1:2016.2.22AR.1+dfsg-1+deb9u1", rls: "DEB9" ) )){
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

