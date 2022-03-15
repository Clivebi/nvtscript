if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892062" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2019-19920" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-22 16:15:00 +0000 (Tue, 22 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-01-10 03:00:06 +0000 (Fri, 10 Jan 2020)" );
	script_name( "Debian LTS: Security Advisory for sa-exim (DLA-2062-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/01/msg00006.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2062-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/946829" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sa-exim'
  package(s) announced via the DLA-2062-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was found that sa-exim, the SpamAssassin filter for Exim, allows
attackers to execute arbitrary code if users are allowed to run custom
rules. A similar issue was fixed in spamassassin, CVE-2018-11805, which
caused a functional regression in sa-exim. This update restores the
compatibility between spamassassin and sa-exim. The security
implications of sa-exim's greylisting function are also documented in
/usr/share/doc/sa-exim/README.greylisting.gz." );
	script_tag( name: "affected", value: "'sa-exim' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
4.2.1-14+deb8u1.

We recommend that you upgrade your sa-exim packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sa-exim", ver: "4.2.1-14+deb8u1", rls: "DEB8" ) )){
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

