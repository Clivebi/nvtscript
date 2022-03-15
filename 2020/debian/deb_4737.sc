if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704737" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2020-4044" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-14 21:15:00 +0000 (Fri, 14 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-07-31 03:00:04 +0000 (Fri, 31 Jul 2020)" );
	script_name( "Debian: Security Advisory for xrdp (DSA-4737-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4737.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4737-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xrdp'
  package(s) announced via the DSA-4737-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Ashley Newson discovered that the XRDP sessions manager was susceptible
to denial of service. A local attacker can further take advantage of
this flaw to impersonate the XRDP sessions manager and capture any user
credentials that are submitted to XRDP, approve or reject arbitrary
login credentials or to hijack existing sessions for xorgxrdp sessions." );
	script_tag( name: "affected", value: "'xrdp' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 0.9.9-1+deb10u1.

We recommend that you upgrade your xrdp packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "xrdp", ver: "0.9.9-1+deb10u1", rls: "DEB10" ) )){
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

